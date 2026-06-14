from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from datetime import datetime
from database import Base
from sqlalchemy import Boolean

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    api_key = Column(String, unique=True, index=True, nullable=True)

    usage_count = Column(Integer, default=0)
    last_usage_reset = Column(DateTime, default=datetime.utcnow)

    plan = Column(String, default="free")
    billing_status = Column(String, default="active")
    role = Column(String, default="user")

    is_disabled = Column(Boolean, default=False)

class LogRecord(Base):
    __tablename__ = "log_records"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    raw_log = Column(Text, nullable=False)
    result = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class BlacklistEntry(Base):
    __tablename__ = "blacklist_entries"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    value = Column(String, nullable=False)
    reason = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class EmailAlertEvent(Base):
    __tablename__ = "email_alert_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)

    source = Column(String, nullable=False)

    escalation_level = Column(String, nullable=False)

    spike_detected = Column(String, default="false")

    status = Column(String, default="pending")

    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

class AdminAuditLog(Base):
    __tablename__ = "admin_audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    admin_email = Column(String)

    action = Column(String)

    target_user = Column(String)

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )