import json
from fastapi import APIRouter, Form, UploadFile, File, Depends
from fastapi.responses import HTMLResponse
import html
from cyber_agent import analyze_security_log
from auth import get_current_user
from models import User, LogRecord, BlacklistEntry
from sqlalchemy.orm import Session
from database import get_db
from api_routes import should_blacklist, extract_indicator_from_log

router = APIRouter()



@router.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
    <html>
        <head>
            <title>Cybersecurity AI Dashboard</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 40px;
                    background: #0f172a;
                    color: white;
                }
                h1 {
                    color: #38bdf8;
            }
            textarea, input, button {
                width: 100%;
                margin-top: 10px;
                margin-bottom: 20px;
                padding: 10px;
                border-radius: 8px;
                border: none;
            }
            textarea {
                height: 180px;
            }
            button {
                background: #38bdf8;
                color: black;
                font-weight: bold;
                cursor: pointer;
            }
            .card {
                background: #1e293b;
                padding: 20px;
                border-radius: 12px;
                margin-bottom: 20px;
            }
        </style>
    </head>
        <body>
        <h1>Cybersecurity AI Dashboard</h1>
        <a href="/live-dashboard" style="color:#38bdf8;">🔥 Go to Live monitor </a>

        <button onclick="logout()" style="
            margin-top: 12px;
            padding: 10px 16px;
            background: #f87171;
            color: white;
            border: none;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
        ">
            Logout
        </button>

        <div class="card">
            <h2>User: <span id="userEmail"></span></h2>
            <h3>Total Logs: <span id="totalLogs">0</span></h3>
            <h3>Anomalies: <span id="anomalyCount">0</span></h3>
        </div>

        <div class="card">
            <h2>Billing / Plan</h2>

            <p>
                Current Plan:
                <span id="current-plan">Loading...</span>
                <span id="pro-badge"></span>
            </p>

            <p>
                Billing Status:
                <span id="billing-status">Loading...</span>
            </p>

            <div style="margin-top:15px;">
                <strong>Daily Usage:</strong>
                <div style="background:#0f172a; border-radius:10px; overflow:hidden; margin-top:8px; border:1px solid #334155;">
                    <div id="usage-bar" style="height:14px; width:0%; background:#22c55e;"></div>
                </div>
                <small id="usage-text">Loading usage...</small>
            </div>

            <div id="upgrade-section" style="margin-top:15px;"></div>

            <p style="margin-top:20px;">
                API Key:
                <span id="api-key">Loading...</span>
            </p>

            <button onclick="toggleApiKey()">Reveal / Hide API Key</button>
            <button onclick="copyApiKey()">Copy API Key</button>
            <button onclick="regenerateApiKey()">Regenerate API Key</button>
        </div>

        <div class="card">
            <h2>Recent Saved Logs</h2>
            <div id="logs"></div>
        </div>

        <div class="card">
            <h2>Analyze Raw Log Text</h2>
            <textarea id="logText" placeholder="Paste security logs here..."></textarea>
            <button type="button" onclick="submitLog()">Analyze Log</button>
            <div id="analyzeResult" style="margin-top:16px;"></div>
        </div>

        <div class="card">
            <h2>Upload Log File</h2>
            <input id="logFile" type="file" name="file">
            <button type="button" onclick="submitUpload()">Upload and Analyze</button>
            <div id="uploadResult" style="margin-top:16px;"></div>
        </div>

        <script>
        let fullApiKey = "";
        let apiKeyVisible = false;

        function logout() {
            localStorage.removeItem("token");
            window.location.href = "/login-page";
        }

        async function submitLog() {
            const token = localStorage.getItem("token");
            const logText = document.getElementById("logText").value;
            const resultBox = document.getElementById("analyzeResult");

            if (!token) {
                window.location.href = "/login-page";
                return;
            }

            if (!logText.trim()) {
                resultBox.innerHTML = "<div style='color:#f87171;'>Please enter a log first.</div>";
                return;
            }

            const formData = new FormData();
            formData.append("log_text", logText);

            const response = await fetch("/analyze-log-form", {
                method: "POST",
                headers: {
                    "Authorization": "Bearer " + token
                },
                body: formData
            });

            const text = await response.text();
            resultBox.innerHTML = text;

            if (response.ok) {
                loadDashboard();
            }
        }

        async function submitUpload() {
            const token = localStorage.getItem("token");
            const fileInput = document.getElementById("logFile");
            const resultBox = document.getElementById("uploadResult");

            if (!token) {
                window.location.href = "/login-page";
                return;
            }

            if (!fileInput.files.length) {
                resultBox.innerHTML = "<div style='color:#f87171;'>Please choose a file first.</div>";
                return;
            }

            const formData = new FormData();
            formData.append("file", fileInput.files[0]);

            const response = await fetch("/upload-log", {
                method: "POST",
                headers: {
                    "Authorization": "Bearer " + token
                },
                body: formData
            });

            const text = await response.text();
            resultBox.innerHTML = text;

            if (response.ok) {
                loadDashboard();
            }
        }

        async function loadDashboard() {
            const token = localStorage.getItem("token");

            if (!token) {
                window.location.href = "/login-page";
                return;
            }

            const response = await fetch("/dashboard-data", {
                headers: {
                    "Authorization": "Bearer " + token
                }
            });

            const billingRes = await fetch("/billing-status", {
                headers: {
                    Authorization: "Bearer " + token
                }
            });

            const billing = await billingRes.json();

            const data = await response.json();
            console.log("dashboard-data:", data);

            document.getElementById("userEmail").innerText = data.email;
            document.getElementById("totalLogs").innerText = data.total_logs;
            document.getElementById("anomalyCount").innerText = data.anomaly_count;
            document.getElementById("current-plan").innerText = billing.plan;
            document.getElementById("billing-status").innerText = billing.billing_status;

            const percent = (billing.usage_count / billing.daily_limit) * 100;

            document.getElementById("usage-bar").style.width = percent + "%";
            document.getElementById("usage-text").innerText =
                `${billing.usage_count} / ${billing.daily_limit} used (${billing.remaining} remaining)`;

            if (billing.plan === "pro") {
                document.getElementById("pro-badge").innerHTML =
                    `<span style="color:#22c55e; font-weight:bold; margin-left:10px;">PRO ✓</span>`;

                document.getElementById("upgrade-section").innerHTML =
                    `<div style="color:#22c55e; font-weight:bold;">You are on Pro.</div>`;
            } else {
                document.getElementById("pro-badge").innerHTML = "";

                document.getElementById("upgrade-section").innerHTML = `
                    <button onclick="upgradeToPro()" style="
                        background:#ef4444;
                        color:white;
                        padding:12px;
                        border:none;
                        border-radius:8px;
                        font-weight:bold;
                        cursor:pointer;
                    ">
                        Upgrade to Pro 🚀
                    </button>
                `;
            }

            const logsContainer = document.getElementById("logs");
            logsContainer.innerHTML = "";

            data.recent_logs.forEach(log => {
                const item = document.createElement("div");

                item.style.padding = "10px";
                item.style.marginBottom = "10px";
                item.style.background = "#1a1a2e";
                item.style.borderRadius = "8px";

                item.innerHTML = `
                    <strong>Log:</strong> ${log.raw_log}<br>
                    <strong>Result:</strong> ${log.result}<br>
                    <small>${log.created_at}</small>
                `;

                logsContainer.appendChild(item);
            });
        }

        async function loadBillingStatus() {
            const token = localStorage.getItem("token");

            const response = await fetch("/billing-status", {
                headers: {
                    "Authorization": "Bearer " + token
                }
            });

            const data = await response.json();

            document.getElementById("current-plan").innerText = data.plan;
            document.getElementById("billing-status").innerText = data.billing_status;
        }

        async function loadApiKey() {
            const token = localStorage.getItem("token");

            const response = await fetch("/my-api-key", {
                headers: {
                    "Authorization": "Bearer " + token
                }
            });

            const data = await response.json();

            fullApiKey = data.api_key;
            apiKeyVisible = false;

            document.getElementById("api-key").innerText =
                "••••••••" + fullApiKey.slice(-4);
        }

        function copyApiKey() {
            navigator.clipboard.writeText(fullApiKey);
            alert("API key copied!");
        }

        function toggleApiKey() {
            apiKeyVisible = !apiKeyVisible;

            const el = document.getElementById("api-key");

            if (apiKeyVisible) {
                el.innerText = fullApiKey;
            } else {
                el.innerText = "••••••••" + fullApiKey.slice(-4);
            }
        }

        async function regenerateApiKey() {
            const token = localStorage.getItem("token");

            const confirmAction = confirm("Are you sure? This will invalidate your old API key.");

            if (!confirmAction) return;

            const response = await fetch("/regenerate-api-key", {
                method: "POST",
                headers: {
                    "Authorization": "Bearer " + token
                }
            });

            const data = await response.json();

            alert("New API key generated");

            fullApiKey = data.api_key;
            apiKeyVisible = false;

            document.getElementById("api-key").innerText =
                "••••••••" + fullApiKey.slice(-4);
                    }

                    async function upgradeToPro() {
                        const token = localStorage.getItem("token");

                        const response = await fetch("/create-checkout-session", {
                            method: "POST",
                            headers: {
                                "Authorization": "Bearer " + token
                            }
                        });

                        const data = await response.json();

                        if (data.url) {
                            window.location.href = data.url;
                        } else {
                            alert("Error creating checkout session");
                        }
                    }            

        async function upgradePlan() {
            const token = localStorage.getItem("token");

            const response = await fetch("/upgrade-plan", {
                method: "POST",
                headers: {
                    "Authorization": "Bearer " + token
                }
            });

            const data = await response.json();
            alert(data.message);

            loadBillingStatus();
        }

        async function downgradePlan() {
            const token = localStorage.getItem("token");

            const response = await fetch("/downgrade-plan", {
                method: "POST",
                headers: {
                    "Authorization": "Bearer " + token
                }
            });

            const data = await response.json();
            alert(data.message);

            loadBillingStatus();
        }

        let socket;

        function connectWebSocket() {
            socket = new WebSocket("ws://127.0.0.1:8000/ws/logs");

            socket.onopen = () => {
                console.log("WebSocket connected");
            };

            socket.onmessage = (event) => {
                const data = JSON.parse(event.data);

                if (data.type === "new_log") {
                    console.log("New log received:", data.log);
                    loadDashboard();
                }
            };

            socket.onclose = () => {
                console.log("WebSocket disconnected, reconnecting...");
                setTimeout(connectWebSocket, 3000);
            };
        }

        window.onload = function() {
            loadDashboard();
            loadBillingStatus();
            loadApiKey();

            connectWebSocket();

            setInterval(() => {
                loadDashboard();
            }, 5000);
        };
        </script>
    </body>
</html>
"""

# Analyze log form submission
@router.post("/analyze-log-form", response_class=HTMLResponse)
def analyze_log_form(
    log_text: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    result = analyze_security_log(log_text)

    record = LogRecord(
        user_id=current_user.id,
        raw_log=log_text,
        result=json.dumps(result)
    )
    db.add(record)
    db.commit()

    should_add, reason = should_blacklist(log_text, result)

    if should_add:
        indicator = extract_indicator_from_log(log_text)

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

    return f"""
    <html>
        <head>
            <title>Analysis Result</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 40px;
                    background: #0f172a;
                    color: white;
                }}
                pre {{
                    background: #1e293b;
                    padding: 20px;
                    border-radius: 12px;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                }}
                a {{
                    color: #38bdf8;
                }}
            </style>
        </head>
        <body>
            <h1>Analysis Result</h1>
            <pre>{html.escape(json.dumps(result, indent=2))}</pre>
            <a href="/dashboard">Back to Dashboard</a>
        </body>
    </html>
    """

@router.get("/login-page", response_class=HTMLResponse)
def login_page():
    return """
    <html>
    <head>
        <title>Login</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #0f172a;
                color: white;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .card {
                background: #1e293b;
                padding: 30px;
                border-radius: 12px;
                width: 350px;
                box-shadow: 0 0 20px rgba(0,0,0,0.3);
            }
            input {
                width: 100%;
                padding: 10px;
                margin-top: 10px;
                margin-bottom: 20px;
                border-radius: 8px;
                border: none;
            }
            button {
                width: 100%;
                padding: 12px;
                background: #38bdf8;
                color: black;
                font-weight: bold;
                border: none;
                border-radius: 8px;
                cursor: pointer;
            }
            #message {
                margin-top: 15px;
                color: #f87171;
            }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>Login</h2>
            <input id="email" type="email" placeholder="Email">
            <input id="password" type="password" placeholder="Password">
            <button onclick="login()">Sign In</button>
            <div id="message"></div>
        </div>

        <script>

        if (localStorage.getItem("token")) {
            window.location.href = "/dashboard";
        }

        async function login() {
            const email = document.getElementById("email").value;
            const password = document.getElementById("password").value;
            const message = document.getElementById("message");

            const response = await fetch("/login", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    email: email,
                    password: password
                })
            });

            const data = await response.json();

            if (!response.ok) {
                message.innerText = data.detail || "Login failed";
                return;
            }

            localStorage.setItem("token", data.access_token);
            window.location.href = "/dashboard";
        }
        </script>
    </body>
    </html>
    """

@router.post("/upload-log", response_class=HTMLResponse)
async def upload_log(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    content = await file.read()
    log_text = content.decode("utf-8", errors="ignore")
    result = analyze_security_log(log_text)

    record = LogRecord(
    user_id=current_user.id,
    raw_log=log_text,
    result=json.dumps(result)
)
    db.add(record)
    db.commit()

    return f"""
    <html>
        <head>
        <title>Uploaded Log Analysis</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 40px;
                    background: #0f172a;
                    color: white;
                }}
                pre {{
                    background: #1e293b;
                    padding: 20px;
                    border-radius: 12px;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                }}
                a {{
                    color: #38bdf8;
                }}
            </style>
        </head>
        <body>
            <h1>Uploaded Log Analysis</h1>
            <h3>Filename: {html.escape(file.filename)}</h3>
            <pre>{html.escape(json.dumps(result, indent=2))}</pre>
            <a href="/dashboard">Back to Dashboard</a>
        </body>
    </html>
    """

@router.get("/analyze-log-ui", response_class=HTMLResponse)
def analyze_log_ui():
    return """
    <html>
        <body style="font-family: Arial; padding: 40px;">
            <h2>Analyze Log</h2>
            <form action="/analyze-log" method="get">
                <input name="log" type="text" style="width:400px;">
                <button type="submit">Analyze</button>
            </form>
        </body>
    </html>
    """

@router.get("/live-dashboard", response_class=HTMLResponse)
def live_dashboard():
    return """
    <html>
    <head>
        <title>Live Security Monitor</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script>

        function logout() {
            localStorage.removeItem("token");
            window.location.href = "/login-page";
        }

        const token = localStorage.getItem("token");
            if (!token) {
                window.location.href = "/login-page";
            }

            let lastAlertCount = 0;
            let allLogs = [];
            let threatChart = null;
            let seenAlerts = new Set();

            async function loadChart() {
                const res = await fetch('/my-metrics', {
                                    headers: { "Authorization": "Bearer " + token }
                                });
                const data = await res.json();

                console.log("METRICS DATA:", data);

                const allScores = data.threat_scores || [];
                const allTimes = data.events || [];

                const recentScores = allScores.slice(-10);
                const recentTimes = allTimes.slice(-10);

                const labels = recentTimes.length === recentScores.length
                    ? recentTimes
                    : recentScores.map((_, i) => `Event ${i + 1}`);

                const canvas = document.getElementById('threatChart');
                if (!canvas) return;

                const ctx = canvas.getContext('2d');

                if (threatChart) {
                    threatChart.destroy();
                }

                threatChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Threat Score',
                            data: recentScores,
                            backgroundColor: '#4fd1c5',
                            borderColor: '#4fd1c5',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {
                            legend: {
                                labels: {
                                    color: '#e5e7eb'
                                }
                            }
                        },
                        scales: {
                            x: {
                                ticks: {
                                    color: '#e5e7eb'
                                },
                                grid: {
                                    color: 'rgba(255,255,255,0.08)'
                                }
                            },
                            y: {
                                beginAtZero: true,
                                suggestedMax: 40,
                                ticks: {
                                    color: '#e5e7eb'
                                },
                                grid: {
                                    color: 'rgba(255,255,255,0.08)'
                                }
                            }
                        }
                    }
                });
            }

            function triggerHighAlertEffects() {
                document.body.classList.add('alert-flash');

                const sound = document.getElementById('alert-sound');
                if (sound) {
                    sound.currentTime = 0;
                    sound.play().catch(() => {});
                }

                setTimeout(() => {
                    document.body.classList.remove('alert-flash');
                }, 1000);
            }

            async function loadTopAttacker() {
                const res = await fetch('/top-attacker', {
                    headers: { "Authorization": "Bearer " + token }
                });

                const data = await res.json();

                const box = document.getElementById('top-attacker-box');
                if (!box) return;

                if (!data.ip) {
                    box.innerHTML = "<div>No attacker data yet</div>";
                    return;
                }

                box.innerHTML = `
                    <div style="font-size:12px; opacity:0.7;">Top Attacker</div>
                    <div style="font-size:20px; font-weight:800; margin-top:6px;">
                        ${data.ip}
                    </div>
                    <div style="margin-top:8px;">
                        Events: ${data.total_events} • 
                        SQL: ${data.sql_count} • 
                        Failed: ${data.failed_count}
                    </div>
                    <div style="margin-top:6px;">
                        Total Score: ${data.total_score}
                    </div>
                `;
            }

            async function loadAlerts() {
                const res = await fetch('/my-alerts', {
                                    headers: { "Authorization": "Bearer " + token }
                                });
                const alerts = await res.json();

                if (alerts.length > lastAlertCount) {
                    const newest = alerts[alerts.length - 1];
                    if (
                        newest &&
                        newest.severity &&
                        ["high", "critical"].includes(newest.severity.toLowerCase())
                    ) {
                        const audio = new Audio("data:audio/wav;base64,UklGRlQAAABXQVZFZm10IBAAAAABAAEAESsAACJWAAACABAAZGF0YTAAAAAA/////wAAAP///wAAAP///wAAAP///wAAAP///wAA");
                        audio.play().catch(() => {});
                    }
                }
                lastAlertCount = alerts.length;

                const box = document.getElementById('alerts-box');
                const historyBox = document.getElementById('alerts-history');

                if (!box || !historyBox) return;

                box.innerHTML = '';
                historyBox.innerHTML = '';

                if (!alerts.length) {
                    box.innerHTML = '<div style="opacity:0.8;">No alerts yet</div>';
                    historyBox.innerHTML = '<div style="opacity:0.6;">No alert history yet</div>';
                    return;
                }

                alerts.slice(-5).reverse().forEach(alert => {
                    const item = document.createElement('div');

                    let borderColor = '#94a3b8';
                    if (alert.severity === 'critical') borderColor = '#ff3b30';
                    if (alert.severity === 'high') borderColor = '#ef4444';
                    if (alert.severity === 'medium') borderColor = '#f59e0b';

                    let attackType = (alert.message.split(' from ')[0] || "GENERAL").toUpperCase();
                    if (alert.is_blacklisted) {
                        attackType += " • BLACKLISTED";
                    }
                    
                    const alertKey = `${alert.severity}:${alert.message}`;

                    if (
                        ["high", "critical"].includes((alert.severity || "").toLowerCase()) &&
                        !seenAlerts.has(alertKey)
                    ) {
                        triggerHighAlertEffects();
                        seenAlerts.add(alertKey);
                    }

                    item.style.marginBottom = '10px';
                    item.style.padding = '12px';
                    item.style.border = `1px solid ${borderColor}`;
                    item.style.borderRadius = '10px';
                    item.style.background = 'rgba(255,255,255,0.03)';

                    if (alert.severity === 'critical') {
                        item.style.boxShadow = '0 0 18px rgba(255, 59, 48, 0.35)';
                    }
                    

                    item.innerHTML = `
                        <div style="font-weight:bold; margin-bottom:6px;">
                            ${(alert.priority || alert.severity).toUpperCase()} • ${attackType}
                            ${alert.count ? `• ${alert.count} event${alert.count === 1 ? "" : "s"}` : ""}
                        </div>
                        <div style="font-size:14px; line-height:1.5;">
                            ${alert.message}
                        </div>
                    `;

                    box.appendChild(item);
                });

                alerts.slice().reverse().forEach(alert => {
                    const item = document.createElement('div');

                    let borderColor = '#94a3b8';
                    if (alert.severity === 'critical') borderColor = '#ff3b30';
                    if (alert.severity === 'high') borderColor = '#ef4444';
                    if (alert.severity === 'medium') borderColor = '#f59e0b';

                    let attackType = (alert.message.split(' from ')[0] || "GENERAL").toUpperCase();
                    if (alert.is_blacklisted) {
                        attackType += " • BLACKLISTED";
                    }
                    
                    item.style.marginBottom = '14px';
                    item.style.padding = '16px';
                    item.style.border = `1px solid ${borderColor}`;
                    item.style.borderRadius = '14px';
                    item.style.background = 'rgba(255,255,255,0.04)';
                    item.style.boxShadow = '0 2px 10px rgba(0,0,0,0.18)';
                    if (alert.severity === 'critical') {
                        item.style.boxShadow = '0 0 18px rgba(255, 59, 48, 0.35)';
                    }
                    item.style.transition = 'all 0.2s ease';
                    item.onmouseenter = () => item.style.transform = 'translateY(-2px)';
                    item.onmouseleave = () => item.style.transform = 'translateY(0)';

                    item.innerHTML = `
                        <div style="font-weight:bold; margin-bottom:4px;">
                            ${(alert.priority || alert.severity).toUpperCase()} • ${attackType}
                            ${alert.count ? `• ${alert.count} event${alert.count === 1 ? "" : "s"}` : ""}
                        </div>
                        <div>${alert.message}</div>
                    `;

                    historyBox.appendChild(item);
                });
            }
                    
            

                async function loadBlacklistCount() {
                    const res = await fetch('/my-blacklist', {
                                        headers: { "Authorization": "Bearer " + token }
                                    });
                    const data = await res.json();

                    const el = document.getElementById('blacklist-count');
                    if (!el) return;

                    el.textContent = data.total_blacklisted || 0;
                }
                
                function renderLogs(data) {

                const priorityOrder = {
                    "critical": 4,
                    "high": 3,
                    "medium": 2,
                    "low": 1
                };

                data.sort((a, b) => {
                    const aPriority =
                        a.priority ||
                        ((a.severity || "").toLowerCase() === "high" ? "high" :
                        (a.severity || "").toLowerCase() === "medium" ? "medium" :
                        "low");

                    const bPriority =
                        b.priority ||
                        ((b.severity || "").toLowerCase() === "high" ? "high" :
                        (b.severity || "").toLowerCase() === "medium" ? "medium" :
                        "low");

                    const pa = priorityOrder[aPriority.toLowerCase()] || 0;
                    const pb = priorityOrder[bPriority.toLowerCase()] || 0;

                    return pb - pa;
                });
                            
                const container = document.getElementById('logs');
                const topThreat = data.length ? data[0] : null;
                const existingTopThreat = document.getElementById('top-threat');

                if (topThreat && (topThreat.priority || "").toLowerCase() !== "low") {
                    const topThreatHtml = `
                        <div style="font-size:12px; opacity:0.7; margin-bottom:6px;">Top Threat</div>
                        <div style="font-size:20px; font-weight:800; margin-bottom:8px; letter-spacing:0.3px;">
                            ${(topThreat.attack_type || "unknown").replace(/_/g, ' ').toUpperCase()}
                        </div>
                        <div style="display:flex; gap:12px; font-size:14px; flex-wrap:wrap; margin-bottom:10px;">
                            <div><b>Priority:</b> ${(topThreat.priority || "").toUpperCase()}</div>
                            <div><b>Severity:</b> ${(topThreat.severity || "").toUpperCase()}</div>
                            <div><b>Score:</b> ${topThreat.threat_score ?? "?"}</div>
                            <div><b>IP:</b> ${topThreat.ip || "?"}</div>
                        </div>
                        <div style="display:flex; gap:12px; font-size:13px; flex-wrap:wrap; opacity:0.9;">
                            <div><b>Total Events:</b> ${topThreat.attacker_history?.total_events || 0}</div>
                            <div><b>Failed Logins:</b> ${topThreat.attacker_history?.failed_login_count || 0}</div>
                            <div><b>SQLi:</b> ${topThreat.attacker_history?.sql_injection_count || 0}</div>
                            <div><b>Blacklisted:</b> ${topThreat.is_blacklisted ? "YES" : "NO"}</div>
                        </div>
                    `;

                    if (existingTopThreat) {
                        if (existingTopThreat.innerHTML !== topThreatHtml) {
                            existingTopThreat.innerHTML = topThreatHtml;
                        }
                    } else {
                        const topThreatBox = document.createElement('div');
                        topThreatBox.id = 'top-threat';
                        topThreatBox.style.cssText = `
                            margin-bottom: 20px;
                            padding: 18px 20px;
                            border-radius: 14px;
                            border: 1px solid rgba(255,255,255,0.12);
                            background: rgba(255,255,255,0.04);
                            display: flex;
                            flex-direction: column;
                            gap: 10px;
                        `;
                        topThreatBox.innerHTML = topThreatHtml;
                        container.parentNode.insertBefore(topThreatBox, container);
                    }
                } else if (existingTopThreat) {
                    existingTopThreat.remove();
                }
                const totalEl = document.getElementById('total-count');
                const failedEl = document.getElementById('failed-count');
                const sqlEl = document.getElementById('sql-count');
                const highEl = document.getElementById('high-count');

                container.innerHTML = "";

                let failedCount = 0;
                let sqlCount = 0;
                let highCount = 0;

                data.slice().reverse().forEach(log => {

                    const displayPriority =
                        log.priority ||
                        ((log.severity || "").toLowerCase() === "high" ? "high" :
                        (log.severity || "").toLowerCase() === "medium" ? "medium" :
                        "low");

                    const failed = log.features?.failed_login || 0;
                    const sql = log.features?.sql_injection || 0;

                    if (failed) failedCount++;
                    if (sql) sqlCount++;

                    let badgeText = log.severity || "LOW";
                    let badgeClass = "badge-low";

                    if (badgeText === "HIGH") {
                        badgeClass = "badge-high";
                    } else if (badgeText === "MEDIUM") {
                        badgeClass = "badge-medium";
                    }

                    if ((log.severity || "LOW") === "HIGH") {
                        highCount++;
                    }

                    const card = document.createElement('div');
                    card.className = log.is_blacklisted ? "log-card blacklisted-card" : "log-card";

                    card.innerHTML = `
                        <div class="card-top">
                            <div class="log-text">${log.log}</div>
                            <div class="badge ${badgeClass}">${badgeText}</div>
                        </div>
                        
                    <div class="meta-row">
                       <div class="meta-box">
                            <span class="meta-label">Blacklist Status</span>
                            <span class="meta-value ${log.is_blacklisted ? 'blacklisted-yes' : 'blacklisted-no'}">
                                ${log.is_blacklisted ? "BLACKLISTED" : "CLEAR"}
                            </span>
                        </div>
                        <div class="meta-box">
                            <span class="meta-label">Prior Events</span>
                            <span class="meta-value">${log.attacker_history?.total_events || 0}</span>
                        </div>
                        <div class="meta-box">
                            <span class="meta-label">Prior Failed Logins</span>
                            <span class="meta-value">${log.attacker_history?.failed_login_count || 0}</span>
                        </div>
                        <div class="meta-box">
                            <span class="meta-label">Prior SQLi</span>
                            <span class="meta-value">${log.attacker_history?.sql_injection_count || 0}</span>
                        </div>
                        <div class="meta-box">
                            <span class="meta-label">Repeat Offender</span>
                            <span class="meta-value">
                                ${(log.attacker_history?.total_events || 0) >= 3 ? "YES" : "NO"}
                            </span>
                        </div>
                    </div>

                        <div class="ai-box">
                            <div class="ai-title">AI Analysis</div>
                            <div class="ai-text">
                                <div style="margin-bottom:8px;"><strong>Attack Type:</strong> ${(log.attack_type || "unknown").replace(/_/g, ' ').toUpperCase()}</div>
                                <div style="margin: 12px 0 16px 0; display: flex; align-items: center; gap: 10px;">
                                <strong style="min-width: 70px;">Priority:</strong>
                                <span style="
                                    display: inline-flex;
                                    align-items: center;
                                    justify-content: center;
                                    padding: 4px 12px;
                                    border-radius: 999px;
                                    font-size: 12px;
                                    font-weight: 700;
                                    letter-spacing: 0.5px;
                                    min-width: 72px;
                                    height: 28px;
                                    background: ${
                                        (displayPriority || "").toLowerCase() === "critical" ? "rgba(255, 59, 48, 0.18)" :
                                        (displayPriority || "").toLowerCase() === "high" ? "rgba(255, 149, 0, 0.18)" :
                                        (displayPriority || "").toLowerCase() === "medium" ? "rgba(255, 204, 0, 0.18)" :
                                        "rgba(120, 130, 150, 0.18)"
                                    };
                                    color: ${
                                        (displayPriority || "").toLowerCase() === "critical" ? "#ff6b6b" :
                                        (displayPriority || "").toLowerCase() === "high" ? "#ffb020" :
                                        (displayPriority || "").toLowerCase() === "medium" ? "#ffd54a" :
                                        "#b8c0cc"
                                    };
                                    border: 1px solid ${
                                        (displayPriority || "").toLowerCase() === "critical" ? "rgba(255, 59, 48, 0.45)" :
                                        (displayPriority || "").toLowerCase() === "high" ? "rgba(255, 149, 0, 0.45)" :
                                        (displayPriority || "").toLowerCase() === "medium" ? "rgba(255, 204, 0, 0.45)" :
                                        "rgba(120, 130, 150, 0.35)"
                                    };
                                ">
                                    ${(displayPriority || "unknown").toUpperCase()}
                                </span>
                            </div>

                                <div><strong>Timestamp:</strong> ${log.timestamp ? log.timestamp.split('T').pop().slice(0, 8) : "unknown"}</div>
                                <div style="margin-top:10px;">${log.ai_analysis || "No analysis available"}</div>
                            </div>
                        </div>
                    `;

                    container.appendChild(card);
                });

                totalEl.textContent = data.length;
                failedEl.textContent = failedCount;
                sqlEl.textContent = sqlCount;
                highEl.textContent = highCount;
        }

        async function loadInitialLogs() {
                const res = await fetch('/my-live-logs', {
                                    headers: { "Authorization": "Bearer " + token }
                                });
                const data = await res.json();
                allLogs = data;
                renderLogs(allLogs);
                loadChart();
                loadAlerts();
                loadBlacklistCount();
        }

            window.onload = async () => {
                await loadInitialLogs();
                loadChart();
                loadAlerts();
                loadBlacklistCount();
                loadTopAttacker();
            };
        </script>

    <style>
        body {
            margin: 0;
            padding: 24px;
            font-family: Arial, sans-serif;
            background: #0f172a;
            color: #e5e7eb;
        }

        .topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            flex-wrap: wrap;
            gap: 12px;
        }

        .title {
            font-size: 36px;
            font-weight: 700;
            color: white;
        }

        .nav-link {
            color: #38bdf8;
            text-decoration: none;
            font-weight: bold;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .stat-card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 14px;
            padding: 18px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.25);
        }

        .stat-label {
            display: block;
            font-size: 13px;
            color: #94a3b8;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .stat-value {
            font-size: 30px;
            font-weight: 700;
            color: white;
        }

        #logs {
    display: flex;
    flex-direction: column;
    gap: 16px;
    margin-top: 24px;
}

        .log-card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 14px;
            padding: 18px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.25);
        }

        .card-top {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 12px;
            margin-bottom: 14px;
        }

        .log-text {
            font-size: 18px;
            font-weight: 700;
            color: #f8fafc;
            word-break: break-word;
        }

        .badge {
            padding: 6px 12px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 700;
            min-width: 70px;
            text-align: center;
        }

        .badge-low {
            background: rgba(34,197,94,0.18);
            color: #4ade80;
            border: 1px solid rgba(34,197,94,0.4);
        }

        .badge-medium {
            background: rgba(234,179,8,0.18);
            color: #facc15;
            border: 1px solid rgba(234,179,8,0.4);
        }

        .badge-high {
            background: rgba(239,68,68,0.18);
            color: #f87171;
            border: 1px solid rgba(239,68,68,0.4);
        }

        .meta-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 12px;
            margin-bottom: 14px;
        }

        .meta-box {
            background: #0f172a;
            border-radius: 10px;
            padding: 12px;
            border: 1px solid #334155;
        }

        .meta-label {
            display: block;
            font-size: 12px;
            color: #94a3b8;
            margin-bottom: 6px;
            text-transform: uppercase;
        }

        .meta-value {
            font-size: 16px;
            font-weight: 700;
            color: #f8fafc;
            word-break: break-word;
        }

        .blacklisted-yes {
            color:#ff4d4d;
            font-weight: bold;
        }

        .blacklisted-no {
            color:#22c55e;
            font-weight: bold;
        }

        .blacklisted-card {
            border: 2px solid #ff4d4d;
            box-shadow: 0 0 12px rgba(255,77,77,0.6);
        }


        .ai-box {
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 14px;
        }

        .ai-title {
            font-size: 13px;
            font-weight: 700;
            color: #38bdf8;
            margin-bottom: 8px;
            text-transform: uppercase;
        }

        .ai-text {
            white-space: pre-wrap;
            word-break: break-word;
            line-height: 1.5;
            color: #e2e8f0;
        }

        .alert-flash {
            animation: flashRed 0.5s ease-in-out 2;
        }

        @keyframes flashRed {
            0% { background-color: #0f172a; }
            50% { background-color: #3f1111; }
            100% { background-color: #0f172a; }
        }
    </style>
</head>

<body>
    <div class="topbar">
    <div class="title">Live Cybersecurity Monitor</div>
    <div style="display:flex; gap:12px; align-items:center;">
        <a href="/dashboard" class="nav-link">Back to Dashboard</a>
        <button onclick="logout()" style="
            padding: 10px 16px;
            background: #f87171;
            color: white;
            border: none;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
        ">
            Logout
        </button>
    </div>
</div>

        <div class="stats">
        <div class="stat-card">
            <span class="stat-label">Total Events</span>
            <span class="stat-value" id="total-count">0</span>
        </div>
        <div class="stat-card">
            <span class="stat-label">Failed Logins</span>
            <span class="stat-value" id="failed-count">0</span>
        </div>
        <div class="stat-card">
            <span class="stat-label">SQL Injection Flags</span>
            <span class="stat-value" id="sql-count">0</span>
        </div>
        <div class="stat-card">
            <span class="stat-label">High Alerts</span>
            <span class="stat-value" id="high-count">0</span>
        </div>
        <div class="stat-card">
            <span class="stat-label">Blacklisted IPs</span>
            <span class="stat-value" id="blacklist-count">0</span>
        </div>
        <div class="stat-card">
            <span class="stat-label">Top Attacker</span>
            <div id="top-attacker-box">Loading...</div>
        </div>
    </div>

    <div class="chart-section">
        <div class="stat-card chart-card">
            <span class="stat-label">Threat Score Trend</span>
            <canvas id="threatChart" height="100"></canvas>
        </div>
    </div>

    <div class="lower-section">
        <div class="stat-card alerts-card">
            <span class="stat-label">Recent Alerts</span>
            <div id="alerts-box" style="margin-top: 12px;"></div>

            <span class="stat-label" style="margin-top: 20px; display:block;">Alert History</span>
            <div id="alerts-history" style="
                margin-top: 12px;
                max-height: 260px;
                overflow-y: auto;
                border-top: 1px solid rgba(255,255,255,0.1);
                padding-top: 10px;
            "></div>
        </div>

        <div id="logs"></div>
    </div>

    <audio id="alert-sound" preload="auto">
        <source src="https://actions.google.com/sounds/v1/alarms/beep_short.ogg" type="audio/ogg">
    </audio>
</body>
</html>
"""