import asyncio
from fastapi import APIRouter, Depends, HTTPException,  Request
from sqlalchemy.orm import Session
from database import get_db
from models import User, LogRecord, BlacklistEntry, EmailAlertEvent
from schemas import UserCreate, UserOut, UserLogin
from auth import hash_password, verify_password, create_access_token, get_current_user
import os
import json
from collections import Counter
from pydantic import BaseModel
import app_state
from metrics_store import get_metrics
from alert_system import get_alerts
from blacklist_store import get_blacklist
from live_processing import attacker_stats
import stripe
from cyber_agent import analyze_security_log
from feature_extraction import extract_features
from anomaly_detector import detect_anomaly
from ai_analyzer import analyzer_with_ai
from ai_router import ai_router
import secrets
from fastapi import Header
from datetime import datetime, timedelta
from api_key_auth import get_user_by_api_key



router = APIRouter()
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
ingestion_errors = []
email_alert_events = []
email_alert_cooldowns = {}

class IngestLogRequest(BaseModel):
    log_text: str
    source: str | None = "api"

class WebhookLogRequest(BaseModel):
    event: str
    source: str = "webhook"
    ip: str | None = None
    severity: str | None = None

def check_and_update_usage(user: User, db: Session):
    now = datetime.utcnow()

    # Handle first-time users
    if not user.last_usage_reset:
        user.last_usage_reset = now
        user.usage_count = 0

    elif user.last_usage_reset < now - timedelta(days=1):
        user.usage_count = 0
        user.last_usage_reset = now

    if user.plan == "free":
        DAILY_LIMIT = 20
    elif user.plan == "pro":
        DAILY_LIMIT = 1000
    else:
        DAILY_LIMIT = 20

    if user.usage_count >= DAILY_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Daily usage limit reached. Limit: {DAILY_LIMIT} logs/day."
        )

    user.usage_count += 1
    db.commit()


def parse_result(record_result: str):
    try:
        return json.loads(record_result)
    except Exception:
        return {}


def extract_indicator_from_log(log_text: str):
    text = log_text.lower()

    if "from " in text:
        try:
            return log_text.split("from ", 1)[1].strip().split()[0]
        except Exception:
            pass

    return log_text.strip()

def should_blacklist(log_text: str, result: dict):
    text = log_text.lower()

    if "sql" in text:
        return True, "sql_injection"

    if "failed" in text and result.get("anomaly") is True:
        return True, "repeated_failed_login"

    return False, None

def should_send_email_alert(escalation_level: str, spike_detected: bool) -> bool:
    return escalation_level in ["high", "critical"] or spike_detected is True

def log_email_alert_placeholder(
    source: str,
    escalation_level: str,
    spike_detected: bool,
    db: Session | None = None
):
    cooldown_key = f"{source}:{escalation_level}"
    now = datetime.utcnow()

    last_sent = email_alert_cooldowns.get(cooldown_key)

    if last_sent:
        minutes_since_last = (now - last_sent).total_seconds() / 60

        if minutes_since_last < 15:
            return

    alert_event = {
        "source": source,
        "escalation_level": escalation_level,
        "spike_detected": spike_detected,
        "timestamp": now.isoformat(),
        "status": "email_pending"
    }

    email_alert_events.append(alert_event)
    email_alert_cooldowns[cooldown_key] = now

    if db:
        db_alert = EmailAlertEvent(
            source=source,
            escalation_level=escalation_level,
            spike_detected=str(spike_detected).lower(),
            status="email_pending"
        )

        db.add(db_alert)
        db.commit()

    print("EMAIL ALERT PLACEHOLDER")
    print(alert_event)

async def broadcast_dashboard_update(log_text: str):
    disconnected = []

    for client in app_state.clients:
        try:
            await client.send_json({
                "type": "new_log",
                "log": log_text
            })
        except Exception:
            disconnected.append(client)

    for client in disconnected:
        if client in app_state.clients:
            app_state.clients.remove(client)

def require_pro_plan(user: User):
    if user.plan != "pro":
        raise HTTPException(
            status_code=403,
            detail="Upgrade to Pro to use this feature"
        )

def classify_attack_type(raw: str):
    if "sql" in raw:
        return "sql_injection"
    if "failed" in raw:
        return "failed_login"
    return "unknown"

def calculate_priority(score: int):
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"

def calculate_smart_score(raw: str, parsed: dict, is_blacklisted: bool, attacker_history: dict):
    score = 0

    # ---------------- BASE SIGNALS ----------------
    if parsed.get("anomaly"):
        score += 25

    if "failed" in raw:
        score += 20

    if "sql" in raw:
        score += 45

    if "multiple" in raw:
        score += 15

    # ---------------- ATTACKER HISTORY ----------------
    total = attacker_history["total_events"]
    failed = attacker_history["failed_login_count"]
    sql = attacker_history["sql_injection_count"]

    if total >= 3:
        score += 10
    if total >= 5:
        score += 15
    if total >= 10:
        score += 25

    if failed >= 3:
        score += 15
    if failed >= 6:
        score += 20

    if sql >= 2:
        score += 20
    if sql >= 5:
        score += 30

    # ---------------- MIXED ATTACK ----------------
    if failed > 0 and sql > 0:
        score += 25

    # ---------------- BLACKLIST ----------------
    if is_blacklisted:
        score += 30

    # ---------------- AGGRESSION ----------------
    if "sql" in raw and "multiple" in raw:
        score += 25

    # ---------------- FINAL ----------------
    return min(score, 100)

@router.post("/ingest-log")
def ingest_log(
    request: IngestLogRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_pro_plan(current_user)
    check_and_update_usage(current_user, db)

    result = analyze_security_log(request.log_text)

    record = LogRecord(
        user_id=current_user.id,
        raw_log=request.log_text,
        result=json.dumps(result)
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    if app_state.main_loop:
        app_state.main_loop.call_soon_threadsafe(
            asyncio.create_task,
            broadcast_dashboard_update(request.log_text)
    )

    return {
        "message": "Log ingested successfully",
        "source": request.source,
        "log_id": record.id,
        "analysis": result
    }

@router.post("/webhook/log-api-key")
def webhook_log_api_key(
    request: WebhookLogRequest,
    current_user: User = Depends(get_user_by_api_key),
    db: Session = Depends(get_db)
):
    try:
        require_pro_plan(current_user)
        check_and_update_usage(current_user, db)

        log_text = request.event

        if request.source:
            log_text += f" from source {request.source}"

        if request.ip:
            log_text += f" from {request.ip}"

        if request.severity:
            log_text += f" severity {request.severity}"

        result = analyze_security_log(log_text)

        result["ingestion_method"] = "api_key_webhook"
        result["source"] = request.source
        result["received_at"] = datetime.utcnow().isoformat()

        record = LogRecord(
            user_id=current_user.id,
            raw_log=log_text,
            result=json.dumps(result)
        )

        db.add(record)
        db.commit()
        db.refresh(record)

        if app_state.main_loop:
            app_state.main_loop.call_soon_threadsafe(
                asyncio.create_task,
                broadcast_dashboard_update(log_text)
            )

        return {
            "status": "success",
            "message": "Webhook log received successfully",
            "log_id": record.id,
            "source": request.source,
            "ip": request.ip,
            "severity": request.severity,
            "analysis": result
        }

    except Exception as e:
        ingestion_errors.append({
            "source": getattr(request, "source", "webhook"),
            "error": str(e),
            "status": "failed",
            "timestamp": datetime.utcnow().isoformat()
        })

        raise

@router.get("/health")
def health():
    return {"status": "ok"}

@router.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    api_key = "sk_" + secrets.token_hex(16)
    new_user = User(
        email=user.email,
        hashed_password=hash_password(user.password),
        api_key=api_key
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
    "id": new_user.id,
    "email": new_user.email,
    "api_key": new_user.api_key
}

@router.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()

    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = create_access_token(data={"sub": db_user.email, "user_id": db_user.id})

    return {
    "access_token": token,
    "token_type": "bearer",
    "user_id": db_user.id,
    "email": db_user.email
}

@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.get("/my-metrics")
def get_my_metrics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    records = (
        db.query(LogRecord)
        .filter(LogRecord.user_id == current_user.id)
        .order_by(LogRecord.id.asc())
        .all()
    )

    events = []
    threat_scores = []

    for record in records:
        parsed = parse_result(record.result)
        created_at = record.created_at.strftime("%H:%M:%S") if record.created_at else "unknown"

        events.append(created_at)

        score = 0
        if parsed.get("anomaly") is True:
            score += 40
        if "sql" in record.raw_log.lower():
            score += 40
        if "failed" in record.raw_log.lower():
            score += 20

        threat_scores.append(min(score, 100))

    return {
        "events": events[-20:],
        "threat_scores": threat_scores[-20:]
    }

@router.get("/alerts")
def get_alerts_api():
    return get_alerts()

@router.get("/my-alerts")
def get_my_alerts(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    records = (
        db.query(LogRecord)
        .filter(LogRecord.user_id == current_user.id)
        .order_by(LogRecord.id.desc())
        .limit(50)
        .all()
    )

    alerts = []

    from collections import defaultdict

    alerts_map = defaultdict(lambda: {
        "count": 0,
        "latest_log": "",
        "attack_type": "unknown",
        "severity": "low",
        "timestamp": None,
        "is_blacklisted": False
    })

    for record in records:
        parsed = parse_result(record.result)
        raw = record.raw_log.lower()

        indicator = extract_indicator_from_log(record.raw_log)
        attack_type = classify_attack_type(raw)

        existing_blacklist = (
            db.query(BlacklistEntry)
            .filter(
                BlacklistEntry.user_id == current_user.id,
                BlacklistEntry.value == indicator
            )
            .first()
        )

        is_blacklisted = existing_blacklist is not None

        # simple scoring (reuse idea from live logs)
        attacker_history = {
            "total_events": 0,
            "failed_login_count": 0,
            "sql_injection_count": 0
        }

        score = calculate_smart_score(raw, parsed, is_blacklisted, attacker_history)

        score = min(score, 100)
        priority = calculate_priority(score)

        key = f"{indicator}:{attack_type}"

        alerts_map[key]["count"] += 1
        alerts_map[key]["latest_log"] = record.raw_log
        alerts_map[key]["attack_type"] = attack_type
        alerts_map[key]["severity"] = priority
        alerts_map[key]["timestamp"] = record.created_at.isoformat() if record.created_at else None
        alerts_map[key]["is_blacklisted"] = is_blacklisted

    alerts = []

    for key, data in alerts_map.items():
        if data["severity"] in ["medium", "high", "critical"]:
            alerts.append({
                "message": data["latest_log"],
                "severity": data["severity"],
                "priority": data["severity"],
                "attack_type": data["attack_type"],
                "timestamp": data["timestamp"],
                "is_blacklisted": data["is_blacklisted"],
                "count": data["count"]
            })

    return alerts

@router.get("/attacker-stats")
def get_attacker_stats():
    return attacker_stats

@router.get("/blacklist")
def get_blacklisted_ips():
    data = get_blacklist()
    return {
        "total_blacklisted": len(data),
        "blacklisted_ips": list(data.keys())
    }

@router.get("/analyze-log")
def analyze_log_get(log: str):
    result = analyze_security_log(log)
    return result

@router.get("/my-live-logs")
def get_my_live_logs(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    records = (
        db.query(LogRecord)
        .filter(LogRecord.user_id == current_user.id)
        .order_by(LogRecord.id.desc())
        .limit(100)
        .all()
    )

    output = []

    for record in reversed(records):
        parsed = parse_result(record.result)
        raw = record.raw_log.lower()

        # -------- ATTACK TYPE --------
        attack_type = classify_attack_type(raw)

        # -------- INDICATOR --------
        indicator = extract_indicator_from_log(record.raw_log)

        # -------- BLACKLIST CHECK --------
        existing_blacklist = (
            db.query(BlacklistEntry)
            .filter(
                BlacklistEntry.user_id == current_user.id,
                BlacklistEntry.value == indicator
            )
            .first()
        )

        is_blacklisted = existing_blacklist is not None

        # -------- ATTACKER HISTORY --------
        matching_records = (
            db.query(LogRecord)
            .filter(LogRecord.user_id == current_user.id)
            .all()
        )

        total_events = 0
        failed_login_count = 0
        sql_injection_count = 0

        for past_record in matching_records:
            past_indicator = extract_indicator_from_log(past_record.raw_log)
            past_raw = past_record.raw_log.lower()

            if past_indicator == indicator:
                total_events += 1

                if "failed" in past_raw:
                    failed_login_count += 1

                if "sql" in past_raw:
                    sql_injection_count += 1

        attacker_history = {
            "total_events": total_events,
            "failed_login_count": failed_login_count,
            "sql_injection_count": sql_injection_count
        }

        # -------- SCORE --------
        score = calculate_smart_score(raw, parsed, is_blacklisted, attacker_history)

        # -------- PRIORITY / SEVERITY --------
        priority = calculate_priority(score)
        severity = priority.upper()

        output.append({
            "log": record.raw_log,
            "anomaly": parsed.get("anomaly", False),
            "severity": severity,
            "priority": priority,
            "ai_analysis": parsed.get("analysis", "No analysis available"),
            "attack_type": attack_type,
            "timestamp": record.created_at.isoformat() if record.created_at else None,
            "features": {},
            "ip": indicator,
            "attacker_history": attacker_history,
            "is_blacklisted": is_blacklisted,
            "threat_score": score
        })

    return output

@router.post("/analyze")
def analyze_log_post(log: str):
    features = extract_features(log)
    anomaly = detect_anomaly(features)
    ai_result = analyzer_with_ai(log)

    return {
        "features": features,
        "anomaly": anomaly,
        "ai_analysis": ai_result
    }

@router.get("/live-logs")
def get_live_logs():
    return app_state.live_logs

@router.get("/test-keys")
def test_keys():
    return {
        "openai": bool(os.getenv("OPENAI_API_KEY")),
        "anthropic": bool(os.getenv("ANTHROPIC_API_KEY"))
    }

@router.get("/run-ai")
def run_ai(task: str):
    result = ai_router(task)
    return {"response": result}

@router.get("/")
def home():
    return {"message": "AI Cybersecurity platform is running!"}

@router.post("/analyze-log-user")
def analyze_log_user(
    log: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    result = analyze_security_log(log)

    record = LogRecord(
        user_id=current_user.id,
        raw_log=log,
        result=json.dumps(result),
    )

    db.add(record)
    db.commit()

    should_add, reason = should_blacklist(log, result)

    if should_add:
        indicator = extract_indicator_from_log(log)

        existing = (
            db.query(BlacklistEntry)
            .filter(
                BlacklistEntry.user_id == current_user.id,
                BlacklistEntry.value == indicator
            )
            .first()
        )

        if not existing:
            entry = BlacklistEntry(
                user_id=current_user.id,
                value=indicator,
                reason=reason
            )
            db.add(entry)
            db.commit()

    db.refresh(record)

    return {
        "message": "Log analyzed and saved",
        "record_id": record.id,
        "user_id": current_user.id,
        "result": result
    }

@router.get("/my-logs")
def get_my_logs(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    records = (
        db.query(LogRecord)
        .filter(LogRecord.user_id == current_user.id)
        .order_by(LogRecord.id.desc())
        .all()
    )

    return [
        {
            "id": record.id,
            "raw_log": record.raw_log,
            "result": record.result,
            "created_at": record.created_at
        }
        for record in records
    ]

@router.get("/my-logs/{record_id}")
def get_my_log_by_id(
    record_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    record = (
        db.query(LogRecord)
        .filter(
            LogRecord.id == record_id,
            LogRecord.user_id == current_user.id
        )
        .first()
    )

    if record is None:
        raise HTTPException(status_code=404, detail="Log record not found")

    return {
        "id": record.id,
        "raw_log": record.raw_log,
        "result": record.result,
        "created_at": record.created_at
    }
@router.get("/source-analytics")
def source_analytics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    records = (
        db.query(LogRecord)
        .filter(LogRecord.user_id == current_user.id)
        .all()
    )

    source_counts = {}
    source_trends = {}
    source_last_seen = {}
    today = datetime.utcnow().date()
    logs_today = 0
    total_logs = 0

    halfway = max(len(records) // 2, 1)

    for index, record in enumerate(records):
        if record.created_at and record.created_at.date() == today:
            logs_today += 1

        parsed = parse_result(record.result)
        source = parsed.get("source")
        
        if not source:
            if parsed.get("ingestion_method") == "api_key_webhook":
                source = "api-webhook"
            elif "source" in record.raw_log.lower():
                source = "external-source"
            else:
                source = "manual-entry"

        if record.created_at:
            source_last_seen[source] = record.created_at.isoformat()

        if source not in source_counts:
            source_counts[source] = 0

        source_counts[source] += 1

        if source not in source_trends:
            source_trends[source] = {
                "recent_events": 0,
                "older_events": 0
            }

        if index >= halfway:
            source_trends[source]["recent_events"] += 1
        else:
            source_trends[source]["older_events"] += 1

    total_logs = sum(source_counts.values())

    top_source = None
    top_count = 0

    noisy_sources = []
    suspicious_sources = []
    source_health = []

    if source_counts:
        top_source, top_count = max(source_counts.items(), key=lambda item: item[1])

        for source, count in source_counts.items():
            if count >= 5:
                noisy_sources.append({
                    "source": source,
                    "count": count,
                    "reason": "High ingestion volume"
                })

            score = 0
            score += count * 2

            matching_records = []

            for r in records:
                parsed_r = parse_result(r.result)
                parsed_source = parsed_r.get("source")

                if not parsed_source:
                    if parsed_r.get("ingestion_method") == "api_key_webhook":
                        parsed_source = "api-webhook"
                    elif "source" in r.raw_log.lower():
                        parsed_source = "external-source"
                    else:
                        parsed_source = "manual-entry"

                if parsed_source == source:
                    matching_records.append(r)

            for r in matching_records:
                parsed = parse_result(r.result)

                if str(parsed.get("severity", "")).lower() == "high":
                    score += 15

                if str(parsed.get("severity", "")).lower() == "critical":
                    score += 30

                if parsed.get("is_blacklisted"):
                    score += 25

                if parsed.get("anomaly") is True:
                    score += 10

                attack_type = parsed.get("attack_type", "")

                if attack_type == "sql_injection":
                    score += 20

                if attack_type == "failed_login":
                    score += 8

            risk_level = "low"

            if score >= 100:
                risk_level = "critical"
            elif score >= 70:
                risk_level = "high"
            elif score >= 40:
                risk_level = "medium"

            health_status = "healthy"

            if count >= 15:
                health_status = "degraded"

            if count >= 30:
                health_status = "offline"

            if score >= 70:
                health_status = "suspicious"

            trend = source_trends.get(source, {})
            older = trend.get("older_events", 0)
            recent = trend.get("recent_events", 0)

            if older == 0 and recent > 0:
                growth = 100
            elif older > 0:
                growth = round(((recent - older) / older) * 100, 2)
            else:
                growth = 0

            spike_detected = recent >= older * 2 and recent >= 5

            escalation_level = "normal"

            if score >= 100 or spike_detected:
                escalation_level = "critical"
            elif score >= 70:
                escalation_level = "high"
            elif count >= 10 or growth >= 50:
                escalation_level = "elevated"

            last_seen_value = source_last_seen.get(source)
            source_uptime_status = "unknown"

            if last_seen_value:
                try:
                    last_seen_dt = datetime.fromisoformat(last_seen_value)
                    minutes_since_seen = (datetime.utcnow() - last_seen_dt).total_seconds() / 60

                    if minutes_since_seen <= 10:
                        source_uptime_status = "active"
                    elif minutes_since_seen <= 60:
                        source_uptime_status = "stale"
                    else:
                        source_uptime_status = "inactive"
                except Exception:
                    source_uptime_status = "unknown"

            if should_send_email_alert(escalation_level, spike_detected):
                log_email_alert_placeholder(
                    source,
                    escalation_level,
                    spike_detected,
                    db
                )

            source_health.append({
                "source": source,
                "status": health_status,
                "count": count,
                "last_seen": source_last_seen.get(source),
                "uptime_status": source_uptime_status,
                "recent_events": recent,
                "older_events": older,
                "growth_percent": growth,
                "spike_detected": spike_detected,
                "escalation_level": escalation_level
            })

            if score >= 40:
                suspicious_sources.append({
                    "source": source,
                    "count": count,
                    "score": score,
                    "risk_level": risk_level,
                    "reason": "Suspicious activity detected from source"
                })

    suspicious_sources.sort(key=lambda item: item["score"], reverse=True)
    noisy_sources.sort(key=lambda item: item["count"], reverse=True)

    return {
        "total_logs": total_logs,
        "logs_today": logs_today,
        "total_sources": len(source_counts),
        "top_source": top_source,
        "top_source_count": top_count,
        "sources": source_counts,
        "noisy_sources": noisy_sources,
        "suspicious_sources": suspicious_sources,
        "source_health": source_health,
    }

@router.get("/dashboard-data")
def get_dashboard_data(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    records = (
        db.query(LogRecord)
        .filter(LogRecord.user_id == current_user.id)
        .order_by(LogRecord.id.desc())
        .limit(20)
        .all()
    )

    total_logs = len(records)
    anomaly_count = sum(1 for record in records if "anomaly': True" in str(record.result) or '"anomaly": true' in str(record.result).lower())

    return {
        "user_id": current_user.id,
        "email": current_user.email,
        "total_logs": total_logs,
        "anomaly_count": anomaly_count,
        "recent_logs": [
            {
                "id": record.id,
                "raw_log": record.raw_log,
                "result": record.result,
                "created_at": record.created_at
            }
            for record in records
        ]
    }

@router.get("/my-blacklist")
def get_my_blacklist(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    entries = (
        db.query(BlacklistEntry)
        .filter(BlacklistEntry.user_id == current_user.id)
        .order_by(BlacklistEntry.id.desc())
        .all()
    )

    return {
        "total_blacklisted": len(entries),
        "blacklisted_ips": [
            {
                "value": entry.value,
                "reason": entry.reason,
                "created_at": entry.created_at.isoformat() if entry.created_at else None
            }
            for entry in entries
        ]
    }

@router.get("/top-attacker")
def get_top_attacker(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    records = (
        db.query(LogRecord)
        .filter(LogRecord.user_id == current_user.id)
        .all()
    )

    attacker_map = {}

    for record in records:
        raw = record.raw_log.lower()
        parsed = parse_result(record.result)

        indicator = extract_indicator_from_log(record.raw_log)

        if indicator not in attacker_map:
            attacker_map[indicator] = {
                "count": 0,
                "sql": 0,
                "failed": 0,
                "score": 0
            }

        attacker_map[indicator]["count"] += 1

        if "sql" in raw:
            attacker_map[indicator]["sql"] += 1

        if "failed" in raw:
            attacker_map[indicator]["failed"] += 1

        # simple scoring accumulation
        score = 0
        if parsed.get("anomaly"):
            score += 25
        if "sql" in raw:
            score += 45
        if "failed" in raw:
            score += 20

        attacker_map[indicator]["score"] += score

    if not attacker_map:
        return {}

    top = max(attacker_map.items(), key=lambda x: x[1]["score"])

    return {
        "ip": top[0],
        "total_events": top[1]["count"],
        "sql_count": top[1]["sql"],
        "failed_count": top[1]["failed"],
        "total_score": top[1]["score"]
    }

@router.post("/api/analyze")
def analyze_log_api(
    log: str,
    user: User = Depends(get_user_by_api_key),
    db: Session = Depends(get_db)
):
    check_and_update_usage(user, db)
    result = analyze_security_log(log)
    raw = log.lower()

    indicator = extract_indicator_from_log(log)

    existing_blacklist = (
        db.query(BlacklistEntry)
        .filter(
            BlacklistEntry.user_id == user.id,
            BlacklistEntry.value == indicator
        )
        .first()
    )

    is_blacklisted = existing_blacklist is not None

    matching_records = (
        db.query(LogRecord)
        .filter(LogRecord.user_id == user.id)
        .all()
    )

    total_events = 0
    failed_login_count = 0
    sql_injection_count = 0

    for past_record in matching_records:
        past_indicator = extract_indicator_from_log(past_record.raw_log)
        past_raw = past_record.raw_log.lower()

        if past_indicator == indicator:
            total_events += 1

            if "failed" in past_raw:
                failed_login_count += 1

            if "sql" in past_raw:
                sql_injection_count += 1

    attacker_history = {
        "total_events": total_events,
        "failed_login_count": failed_login_count,
        "sql_injection_count": sql_injection_count
    }

    score = calculate_smart_score(raw, result, is_blacklisted, attacker_history)
    priority = calculate_priority(score)

    result["threat_score"] = score
    result["priority"] = priority
    result["severity"] = priority.upper()
    result["is_blacklisted"] = is_blacklisted
    result["attacker_history"] = attacker_history
    result["ip"] = indicator

    record = LogRecord(
        user_id=user.id,
        raw_log=log,
        result=json.dumps(result)
    )

    db.add(record)
    db.commit()

    should_add, reason = should_blacklist(log, result)

    if should_add:
        existing = (
            db.query(BlacklistEntry)
            .filter(
                BlacklistEntry.user_id == user.id,
                BlacklistEntry.value == indicator
            )
            .first()
        )

        if not existing:
            entry = BlacklistEntry(
                user_id=user.id,
                value=indicator,
                reason=reason
            )
            db.add(entry)
            db.commit()

    return {
        "result": result,
        "user_id": user.id
    }

@router.post("/create-checkout-session")
def create_checkout_session(user=Depends(get_current_user)):
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            client_reference_id=str(user.id),
            customer_email=user.email,
            metadata={
                "user_id": str(user.id),
                "email": user.email
            },
            line_items=[{
                "price": os.getenv("STRIPE_PRICE_ID"),
                "quantity": 1,
            }],
            success_url=os.getenv("APP_URL") + "/dashboard",
            cancel_url=os.getenv("APP_URL") + "/dashboard",
        )

        return {"url": session.url}

    except Exception as e:
        print("STRIPE ERROR:", str(e))  # 👈 IMPORTANT
        return {"error": str(e)}


@router.get("/success")
def payment_success():
    return {
        "message": "Payment successful. Pro upgrade webhook will be added next."
    }


@router.get("/cancel")
def payment_cancel():
    return {
        "message": "Payment cancelled."
    }

@router.post("/upgrade-plan")
def upgrade_plan(
    plan: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if plan not in ["free", "pro"]:
        raise HTTPException(status_code=400, detail="Invalid plan")

    current_user.plan = plan
    db.commit()

    return {
        "message": f"Plan updated to {plan}",
        "plan": current_user.plan
    }

@router.post("/downgrade-plan")
def downgrade_plan(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    current_user.plan = "free"
    current_user.billing_status = "inactive"

    db.commit()
    db.refresh(current_user)

    return {
        "message": "Plan downgraded to free",
        "plan": current_user.plan,
        "billing_status": current_user.billing_status
    }

@router.get("/billing-status")
def billing_status(
    current_user: User = Depends(get_current_user)
):
    if current_user.plan == "pro":
        daily_limit = 1000
    else:
        daily_limit = 20

    return {
        "plan": current_user.plan,
        "billing_status": current_user.billing_status,
        "usage_count": current_user.usage_count,
        "daily_limit": daily_limit,
        "remaining": max(daily_limit - current_user.usage_count, 0)
    }

@router.get("/my-api-key")
def get_my_api_key(current_user: User = Depends(get_current_user)):
    return {
        "api_key": current_user.api_key
    }

@router.post("/regenerate-api-key")
def regenerate_api_key(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    import secrets

    new_key = "sk_" + secrets.token_hex(16)

    current_user.api_key = new_key
    db.commit()

    return {
        "message": "API key regenerated",
        "api_key": new_key
    }

@router.post("/stripe-webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    try:
        event = await request.json()

        if event["type"] == "checkout.session.completed":
            session = event["data"]["object"]

            metadata = session.get("metadata", {})
            user_id = session.get("client_reference_id") or metadata.get("user_id")
            email = session.get("customer_email") or metadata.get("email")
            subscription_id = session.get("subscription")

            user = None

            if user_id:
                user = db.query(User).filter(User.id == int(user_id)).first()

            if not user and email:
                user = db.query(User).filter(User.email == email).first()

            if user:
                user.plan = "pro"
                user.billing_status = "active"

                if hasattr(user, "stripe_subscription_id"):
                    user.stripe_subscription_id = subscription_id

                db.commit()
                print(f"PAYMENT SUCCESS FOR USER {user.id} - {user.email}")
            else:
                print("PAYMENT SUCCESS BUT USER NOT FOUND:", email, user_id)

        return {"status": "success"}

    except Exception as e:
        print("WEBHOOK ERROR:", str(e))
        return {"error": str(e)}

@router.get("/ingestion-activity")
def ingestion_activity(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    records = (
        db.query(LogRecord)
        .filter(LogRecord.user_id == current_user.id)
        .order_by(LogRecord.id.desc())
        .limit(10)
        .all()
    )

    activity = []

    for record in records:
        parsed = parse_result(record.result)

        activity.append({
            "source": (
                parsed.get("source")
                or (
                    "api-webhook"
                    if parsed.get("ingestion_method") == "api_key_webhook"
                    else "manual-entry"
                )
            ),
            "event": record.raw_log,
            "status": "processed",
            "severity": parsed.get("severity", "LOW"),
            "timestamp": (
                record.created_at.strftime("%H:%M:%S")
                if record.created_at
                else "unknown"
            )
        })

    return {
        "status": "success",
        "activity": activity
    }

@router.get("/ingestion-errors")
def get_ingestion_errors():
    return {
        "status": "success",
        "total_errors": len(ingestion_errors),
        "errors": ingestion_errors[-10:]
    }

@router.get("/email-alerts")
def get_email_alerts(db: Session = Depends(get_db)):
    db_alerts = (
        db.query(EmailAlertEvent)
        .order_by(EmailAlertEvent.id.desc())
        .limit(20)
        .all()
    )

    alerts = [
        {
            "id": alert.id,
            "source": alert.source,
            "escalation_level": alert.escalation_level,
            "spike_detected": alert.spike_detected,
            "status": alert.status,
            "created_at": alert.created_at.isoformat() if alert.created_at else None
        }
        for alert in db_alerts
    ]

    last_alert = alerts[0] if alerts else None

    return {
        "status": "success",
        "total_alerts": len(alerts),
        "active_cooldowns": len(email_alert_cooldowns),
        "last_alert": last_alert,
        "alerts": alerts
    }

@router.post("/test-email-alert")
def test_email_alert(
    db: Session = Depends(get_db)
):
    log_email_alert_placeholder(
        source="test-source",
        escalation_level="critical",
        spike_detected=True,
        db=db
    )

    return {
        "status": "success",
        "message": "Test email alert event created"
    }

@router.post("/acknowledge-alert/{alert_id}")
def acknowledge_alert(
    alert_id: int,
    db: Session = Depends(get_db)
):
    alert = (
        db.query(EmailAlertEvent)
        .filter(EmailAlertEvent.id == alert_id)
        .first()
    )

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = "acknowledged"
    alert.acknowledged_at = datetime.utcnow()

    db.commit()
    db.refresh(alert)

    return {
        "status": "success",
        "message": "Alert acknowledged",
        "alert_id": alert.id,
        "alert_status": alert.status,
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None
    }