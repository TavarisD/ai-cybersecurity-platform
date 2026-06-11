import json
from fastapi import APIRouter, Form, UploadFile, File, Depends, HTTPException
from fastapi.responses import HTMLResponse
import html
from cyber_agent import analyze_security_log
from auth import get_current_user
from models import User, LogRecord, BlacklistEntry
from sqlalchemy.orm import Session
from database import get_db
from api_routes import should_blacklist, extract_indicator_from_log

router = APIRouter()

def require_admin_user(current_user: User):
    if getattr(current_user, "role", "user") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access required"
        )
    return current_user

@router.get("/api-docs-page", response_class=HTMLResponse)
def api_docs_page():
    return """
    <html>
    <head>
        <title>API Documentation</title>
        <style>
            body {
                background: #0f172a;
                color: white;
                font-family: Arial;
                padding: 40px;
                max-width: 1000px;
                margin: auto;
            }

            pre {
                background: #1e293b;
                padding: 15px;
                border-radius: 8px;
                overflow-x: auto;
            }

            h1,h2 {
                color: #38bdf8;
            }
        </style>
    </head>
    <body>

        <h1>AI Cybersecurity Platform API</h1>

        <h2>Authentication</h2>

        <p>
        Use your API key in the X-API-Key header.
        </p>

        <pre>
X-API-Key: sk_your_api_key
        </pre>

        <h2>Analyze Log</h2>

        <pre>
POST /api/analyze

log=Multiple failed login attempts detected
        </pre>

        <h2>Webhook Ingestion</h2>

        <pre>
POST /webhook/log-api-key

{
  "event": "Multiple failed login attempts",
  "source": "firewall",
  "ip": "203.0.113.45",
  "severity": "high"
}
        </pre>

        <h2>Response Example</h2>

        <pre>
{
  "threat_score": 100,
  "priority": "critical",
  "mitre_mapping": {...},
  "ioc_data": {...}
}
        </pre>

    </body>
    </html>
    """

@router.get("/onboarding", response_class=HTMLResponse)
def onboarding_page():
    return """
    <html>
    <head>
        <title>Customer Onboarding</title>
        <style>
            body {
                background:#0f172a;
                color:white;
                font-family:Arial;
                padding:40px;
                max-width:900px;
                margin:auto;
            }
            .card {
                background:#1e293b;
                padding:20px;
                border-radius:12px;
                margin-bottom:20px;
                border:1px solid #334155;
            }
            h1,h2 {
                color:#38bdf8;
            }
            button {
                width:100%;
                padding:12px;
                border:none;
                border-radius:8px;
                background:#38bdf8;
                color:black;
                font-weight:bold;
                cursor:pointer;
                margin-top:10px;
            }
        </style>
    </head>
    <body>
        <h1>Welcome to AI Cybersecurity Platform</h1>

        <div class="card">
            <h2>Step 1 — Get Your API Key</h2>
            <p>Go to your dashboard and reveal or copy your API key.</p>
            <button onclick="window.location.href='/dashboard'">Open Dashboard</button>
        </div>

        <div class="card">
            <h2>Step 2 — Read the API Docs</h2>
            <p>Review authentication, webhook ingestion, and example requests.</p>
            <button onclick="window.open('/api-docs-page', '_blank')">Open API Docs</button>
        </div>

        <div class="card">
            <h2>Step 3 — Send Your First Log</h2>
            <p>Use the PowerShell or curl example from your dashboard to send a test log.</p>
        </div>

        <div class="card">
            <h2>Step 4 — Check Results</h2>
            <p>Return to your dashboard to see threat score, severity, MITRE mapping, IOC data, and incident status.</p>
        </div>
    </body>
    </html>
    """

@router.get("/usage-analytics-page", response_class=HTMLResponse)
def usage_analytics_page():
    return """
    <html>
    <head>
        <title>Usage Analytics</title>
        <style>
            body {
                background:#0f172a;
                color:white;
                font-family:Arial;
                padding:40px;
                max-width:900px;
                margin:auto;
            }
            .card {
                background:#1e293b;
                padding:20px;
                border-radius:12px;
                margin-bottom:20px;
                border:1px solid #334155;
            }
            h1,h2 {
                color:#38bdf8;
            }
        </style>
    </head>
    <body>
        <h1>Usage Analytics</h1>

        <div class="card">
            <h2>Plan Usage</h2>
            <p>View your current plan, daily API limit, usage count, and remaining requests from the main dashboard Billing / Plan section.</p>
        </div>

        <div class="card">
            <h2>Ingestion Activity</h2>
            <p>Your dashboard shows recent processed logs, ingestion source, severity, and timestamps.</p>
        </div>

        <div class="card">
            <h2>Source Analytics</h2>
            <p>Use Source Trend Analytics to monitor noisy sources, suspicious sources, spikes, and source health.</p>
        </div>

        <div class="card">
            <h2>Upgrade Reminder</h2>
            <p>Free users are limited to 20 logs per day. Pro users receive a higher daily limit.</p>
        </div>
    </body>
    </html>
    """

@router.get("/admin-dashboard", response_class=HTMLResponse)
def admin_dashboard(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_admin_user(current_user)

    total_customers = db.query(User).count()
    free_users = db.query(User).filter(User.plan == "free").count()
    pro_users = db.query(User).filter(User.plan == "pro").count()
    total_logs = db.query(LogRecord).count()

    active_customers = db.query(User).filter(User.usage_count > 0).count()
    inactive_customers = db.query(User).filter(User.usage_count == 0).count()

    top_customer = db.query(User).order_by(User.usage_count.desc()).first()
    top_customer_email = top_customer.email if top_customer else "None"
    top_customer_usage = top_customer.usage_count if top_customer else 0
    conversion_rate = round((pro_users / total_customers) * 100, 2) if total_customers > 0 else 0
    estimated_mrr = pro_users * 29
    estimated_arr = estimated_mrr * 12

    customer_health_score = 0

    if total_customers > 0:
        customer_health_score = round((active_customers / total_customers) * 100, 2)

    launch_readiness_score = 75

    users = db.query(User).order_by(User.id.desc()).all()

    customer_rows = ""

    for user in users:
        customer_rows += f"""
            <tr class="customer-row" data-email="{html.escape(user.email)}" style="border-top:1px solid #334155;">
                <td style="padding:10px;">{html.escape(user.email)}</td>
                <td style="padding:10px;">
                    <span style="
                        background:{'#22c55e' if user.plan == 'pro' else '#475569'};
                        color:white;
                        padding:4px 10px;
                        border-radius:999px;
                        font-size:12px;
                        font-weight:bold;
                    ">
                        {user.plan.upper()}
                    </span>
                </td>
                <td style="padding:10px;">{user.billing_status}</td>
                <td style="padding:10px;">
                    <span style="
                        background:{'#7c3aed' if getattr(user, 'role', 'user') == 'admin' else '#334155'};
                        color:white;
                        padding:4px 10px;
                        border-radius:999px;
                        font-size:12px;
                        font-weight:bold;
                    ">
                        {getattr(user, "role", "user").upper()}
                    </span>
                </td>
                <td style="padding:10px;">
                    {user.usage_count} requests
                </td>
                <td style="padding:10px;">
                    {getattr(user, "last_login_at", "Never")}
                </td>
                <td style="padding:10px;">
                    <button
                        onclick="openCustomerManager('{user.id}', '{html.escape(user.email)}', '{user.plan}', '{getattr(user, "role", "user")}')"
                        style="
                            background:#1d4ed8;
                            color:white;
                            border:none;
                            padding:6px 10px;
                            border-radius:6px;
                            cursor:pointer;
                        "
                    >
                    Manage User
                    </button>
                </td>
            </tr>
        """

    return f"""
    <html>
    <head>
        <title>Admin Dashboard</title>
        <style>
            body {{
                background:#0f172a;
                color:white;
                font-family:Arial;
                padding:40px;
                max-width:1300px;
                margin:auto;
            }}
            .grid {{
                display:grid;
                grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
                gap:20px;
            }}
            .card {{
                background:#1e293b;
                padding:20px;
                border-radius:12px;
                border:1px solid #334155;
            }}
            h1 {{
                color:#38bdf8;
            }}
            .number {{
                font-size:32px;
                font-weight:bold;
                color:#22c55e;
            }}
            table {{
                width:100%;
                border-collapse:collapse;
                margin-top:15px;
            }}
            th {{
                text-align:left;
                color:#38bdf8;
                padding:10px;
            }}
        </style>
    </head>
    <body>
        <h1>Admin Dashboard</h1>

        <div class="card" style="margin-bottom:25px; border:1px solid #38bdf8;">
            <h2>Platform Status</h2>
            <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px;">
                <div>
                    <strong>Status:</strong><br>
                    <span style="color:#22c55e;font-weight:bold;">Operational</span>
                </div>
                <div>
                    <strong>Billing Mode:</strong><br>
                    <span style="color:#fbbf24;font-weight:bold;">Test Mode</span>
                </div>
                <div>
                    <strong>Launch Phase:</strong><br>
                    <span style="color:#38bdf8;font-weight:bold;">Pre-Production</span>
                </div>
                <div>
                    <strong>Next Action:</strong><br>
                    <span style="color:#c084fc;font-weight:bold;">Stripe Live Billing</span>
                </div>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h2>Total Customers</h2>
                <div class="number">{total_customers}</div>
                <small>All registered accounts</small>
            </div>

            <div class="card">
                <h2>Free Users</h2>
                <div class="number">{free_users}</div>
                <small>Trial / free-tier users</small>
            </div>

            <div class="card">
                <h2>Pro Users</h2>
                <div class="number">{pro_users}</div>
                <small>Paying subscription users</small>
            </div>

            <div class="card">
                <h2>Total Logs Processed</h2>
                <div class="number">{total_logs}</div>
                <small>All customer security logs</small>
            </div>

            <div class="card">
            <h2>Active Customers</h2>
            <div class="number">{active_customers}</div>
            <small>Customers with usage</small>
        </div>

        <div class="card">
            <h2>Inactive Customers</h2>
            <div class="number">{inactive_customers}</div>
            <small>No usage yet</small>
        </div>

        <div class="card">
            <h2>Top Customer</h2>
            <div style="font-size:14px; color:#94a3b8; word-break:break-all;">
                {html.escape(top_customer_email)}
            </div>
            <div class="number">{top_customer_usage}</div>
            <small>requests</small>
        </div>
    </div>
        <div class="card" style="margin-top:25px;">
            <h2>Founder Analytics</h2>

            <div class="grid">
                <div class="card">
                    <h2>Estimated MRR</h2>
                    <div class="number">${estimated_mrr}</div>
                    <small>Based on Pro users at $29/mo</small>
                </div>

                <div class="card">
                    <h2>Estimated ARR</h2>
                    <div class="number">${estimated_arr}</div>
                    <small>Annualized recurring revenue</small>
                </div>

                <div class="card">
                    <h2>Pro Conversion</h2>
                    <div class="number">{conversion_rate}%</div>
                    <small>Pro users / total customers</small>
                </div>

                <div class="card">
                    <h2>Retention</h2>
                    <div class="number">TBD</div>
                    <small>Coming after real subscription history</small>
                </div>
            </div>
        </div>

        <div class="card" style="margin-top:25px;">
            <h2>Executive Overview</h2>

            <div class="grid">
                <div class="card">
                    <h2>Customer Health</h2>
                    <div class="number">{customer_health_score}%</div>
                    <small>Active customers / total customers</small>
                </div>

                <div class="card">
                    <h2>Launch Readiness</h2>
                    <div class="number">{launch_readiness_score}%</div>
                    <small>Estimated based on completed platform phases</small>
                </div>

                <div class="card">
                    <h2>Revenue Stage</h2>
                    <div class="number">Test</div>
                    <small>Stripe is still in test mode</small>
                </div>

                <div class="card">
                    <h2>Next Milestone</h2>
                    <div style="font-size:20px;font-weight:bold;color:#38bdf8;">
                        Production Billing
                    </div>
                    <small>Move Stripe from test mode to live subscriptions</small>
                </div>
            </div>
        </div>

        <div class="card" style="margin-top:25px;">
            <h2>Customer Management</h2>

            <input
                type="text"
                id="customerSearch"
                placeholder="Search customers by email..."
                onkeyup="filterCustomers()"
                style="
                    width:100%;
                    padding:12px;
                    margin-top:10px;
                    border-radius:8px;
                    border:none;
                    background:#0f172a;
                    color:white;
                "
            >

            <table>
                <thead>
                    <tr>
                        <th>Email</th>
                        <th>Plan</th>
                        <th>Billing</th>
                        <th>Role</th>
                        <th>Usage</th>
                        <th>Last Login</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {customer_rows}
                </tbody>
            </table>

            <div id="customer-manager" style="
                display:none;
                margin-top:20px;
                background:#020617;
                padding:20px;
                border-radius:12px;
                border:1px solid #38bdf8;
            ">
                <h2>Customer Manager</h2>

                <p><strong>Email:</strong> <span id="manager-email"></span></p>
                <p><strong>User ID:</strong> <span id="manager-user-id"></span></p>
                <p><strong>Plan:</strong> <span id="manager-plan"></span></p>
                <p><strong>Role:</strong> <span id="manager-role"></span></p>

                <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:10px; margin-top:15px;">
                    <button onclick="runAdminAction('promote-user')" style="background:#2563eb;color:white;">Promote</button>
                    <button onclick="runAdminAction('demote-user')" style="background:#64748b;color:white;">Demote</button>
                    <button onclick="runAdminAction('force-pro')" style="background:#16a34a;color:white;">Force Pro</button>
                    <button onclick="runAdminAction('force-free')" style="background:#ca8a04;color:white;">Force Free</button>
                    <button onclick="runAdminAction('disable-user')" style="background:#dc2626;color:white;">Disable</button>
                    <button onclick="runAdminAction('enable-user')" style="background:#22c55e;color:white;">Enable</button>
                </div>

                <div id="admin-action-result" style="margin-top:15px;"></div>
            </div>

            <div class="card" style="margin-top:25px;">
                <h2>Business Metrics</h2>

                <div id="admin-metrics-box" style="
                    margin-top:15px;
                    min-height:120px;
                ">
                    <div style="opacity:0.7;">
                        Click below to load business metrics
                    </div>
                </div>

                <button onclick="loadAdminMetrics()">
                    Reload Business Metrics
                </button>
            </div>

        </div>

        <script>
        let selectedUserId = null;

        function filterCustomers() {{
            const search = document.getElementById("customerSearch").value.toLowerCase();
            const rows = document.querySelectorAll(".customer-row");

            rows.forEach(row => {{
                const email = row.dataset.email.toLowerCase();
                row.style.display = email.includes(search) ? "" : "none";
            }});
        }}

        function openCustomerManager(userId, email, plan, role) {{
            selectedUserId = userId;

            document.getElementById("customer-manager").style.display = "block";
            document.getElementById("manager-email").innerText = email;
            document.getElementById("manager-user-id").innerText = userId;
            document.getElementById("manager-plan").innerText = plan;
            document.getElementById("manager-role").innerText = role;
            document.getElementById("admin-action-result").innerHTML = "";
        }}

        async function runAdminAction(action) {{
            if (!selectedUserId) {{
                alert("Select a customer first.");
                return;
            }}

            const token = localStorage.getItem("token");

            const response = await fetch("/admin/" + action + "/" + selectedUserId, {{
                method: "POST",
                headers: {{
                    "Authorization": "Bearer " + token
                }}
            }});

            const data = await response.json();

            if (!response.ok) {{
                document.getElementById("admin-action-result").innerHTML =
                    "<div style='color:#f87171;font-weight:bold;'>" + (data.detail || "Action failed") + "</div>";
                return;
            }}

            document.getElementById("admin-action-result").innerHTML =
                "<div style='color:#22c55e;font-weight:bold;'>" + data.message + "</div>";
        }}

        async function loadAdminMetrics() {{
            const token = localStorage.getItem("token");

            const revenueRes = await fetch("/admin/revenue-metrics", {{
                headers: {{
                    "Authorization": "Bearer " + token
                }}
            }});

            const growthRes = await fetch("/admin/growth-metrics", {{
                headers: {{
                    "Authorization": "Bearer " + token
                }}
            }});

            const auditRes = await fetch("/admin/audit-logs", {{
                headers: {{
                    "Authorization": "Bearer " + token
                }}
            }});

            const revenue = await revenueRes.json();
            const growth = await growthRes.json();
            const audit = await auditRes.json();

            let auditHtml = "";

            if (audit.logs && audit.logs.length > 0) {{
                audit.logs.slice(0, 10).forEach(log => {{
                    auditHtml +=
                        "<div style='margin-top:8px;padding:8px;background:#0f172a;border-radius:8px;'>" +
                        "<strong>" + log.action + "</strong> — " +
                        log.target_user + "<br><small>" +
                        log.admin_email + " | " + log.created_at +
                        "</small></div>";
                }});
            }} else {{
                auditHtml = "<div>No audit logs yet.</div>";
            }}

            document.getElementById("admin-metrics-box").innerHTML =
                "<div style='display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;'>" +
                "<div class='card'><h3>Monthly Revenue</h3><div class='number'>$" + revenue.estimated_mrr + "</div></div>" +
                "<div class='card'><h3>Conversion Rate</h3><div class='number'>" + revenue.conversion_rate + "%</div></div>" +
                "<div class='card'><h3>Disabled Accounts</h3><div class='number'>" + revenue.disabled_users + "</div></div>" +
                "<div class='card'><h3>New Customers</h3><div class='number'>" + growth.new_users_week + "</div></div>" +
                "</div>" +
                "<h3 style='margin-top:20px;'>Recent Admin Actions</h3>" +
                auditHtml;
        }}
        loadAdminMetrics();
        </script>

    </body>
    </html>
    """

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

            @keyframes heartbeatPulse {
                0% {
                    transform: scale(1);
                    opacity: 0.8;
                }
                50% {
                    transform: scale(1.35);
                    opacity: 1;
                }
                100% {
                    transform: scale(1);
                    opacity: 0.8;
                }
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

            <div style="
                margin-top:-10px;
                margin-bottom:15px;
                color:#fbbf24;
                font-size:13px;
            ">
                Warning: regenerating your API key will immediately disable your old key.
            </div>

            <button onclick="window.open('/api-docs-page', '_blank')">
                API Documentation
            </button>

            <div style="
                margin-top:20px;
                background:#020617;
                padding:15px;
                border-radius:10px;
                border:1px solid #38bdf8;
            ">
                <h3>Quick Start</h3>
                <ol style="line-height:1.8;">
                    <li>Reveal or copy your API key.</li>
                    <li>Open the API Documentation page.</li>
                    <li>Copy the PowerShell or curl example below.</li>
                    <li>Send your first test log.</li>
                    <li>Refresh the dashboard and confirm the log appears.</li>
                </ol>
            </div>

            <button onclick="window.open('/onboarding', '_blank')">
                Open Customer Onboarding
            </button>

            <button onclick="window.open('/usage-analytics-page', '_blank')">
                Open Usage Analytics
            </button>

            <button onclick="openAdminDashboard()">
                Open Admin Dashboard
            </button>

            <div style="margin-top:20px; background:#0f172a; padding:15px; border-radius:10px; border:1px solid #334155;">
                <h3>External Log Ingestion</h3>
                <p>Send logs from external systems using your API key.</p>

                <pre style="white-space:pre-wrap; background:#020617; padding:12px; border-radius:8px; color:#38bdf8;">POST /webhook/log-api-key

                
Headers:
Content-Type: application/json
X-API-Key: YOUR_API_KEY

Body:
{
  "event": "Failed login attempt",
  "source": "external-firewall",
  "ip": "203.0.113.45",
  "severity": "high"
}
</pre>

                <button onclick="copyWebhookExample()">Copy Example Request</button>
                <button onclick="copyPowerShellExample()">Copy PowerShell Example</button>
                <button onclick="copyCurlExample()">Copy curl Example</button>
            </div>
            <div style="margin-top:20px; background:#0f172a; padding:15px; border-radius:10px; border:1px solid #334155;">
                <h3>Ingestion Monitoring</h3>

                <div style="
                    display:grid;
                    grid-template-columns:repeat(auto-fit, minmax(160px, 1fr));
                    gap:12px;
                    margin-top:15px;
                ">
                    <div style="background:#020617; padding:12px; border-radius:10px; border:1px solid #334155;">
                        <div style="color:#94a3b8; font-size:12px;">Logs Today</div>
                        <div id="logs-today" style="font-size:24px; font-weight:bold;">Loading...</div>
                    </div>

                    <div style="background:#020617; padding:12px; border-radius:10px; border:1px solid #334155;">
                        <div style="color:#94a3b8; font-size:12px;">Total Sources</div>
                        <div id="total-sources" style="font-size:24px; font-weight:bold;">Loading...</div>
                    </div>

                    <div style="background:#020617; padding:12px; border-radius:10px; border:1px solid #334155;">
                        <div style="color:#94a3b8; font-size:12px;">Noisy Sources</div>
                        <div id="noisy-count" style="font-size:24px; font-weight:bold;">0</div>
                    </div>

                    <div style="background:#020617; padding:12px; border-radius:10px; border:1px solid #334155;">
                        <div style="color:#94a3b8; font-size:12px;">Suspicious Sources</div>
                        <div id="suspicious-count" style="font-size:24px; font-weight:bold;">0</div>
                    </div>
                </div>

                <p style="margin-top:15px;">
                    Most Active Source:
                    <strong><span id="top-source">Loading...</span></strong>
                </p>

                <div id="noisy-sources-box" style="
                    margin-top:15px;
                    background:#020617;
                    padding:12px;
                    border-radius:8px;
                "></div>

                <div id="suspicious-sources-box" style="
                    margin-top:15px;
                    background:#1e1b4b;
                    padding:12px;
                    border-radius:8px;
                    border:1px solid #7c3aed;
                "></div>
                <div id="source-list"></div>
                <div style="
                    margin-top:20px;
                    background:#020617;
                    padding:15px;
                    border-radius:10px;
                    border:1px solid #334155;
                ">
                    <h3>Live Ingestion Activity</h3>

                    <div id="ingestion-activity-box" style="
                        margin-top:15px;
                        display:flex;
                        flex-direction:column;
                        gap:12px;
                    ">
                        <div style="opacity:0.7;">Loading activity...</div>
                    </div>
                    <div style="
                        margin-top:20px;
                        background:#450a0a;
                        padding:15px;
                        border-radius:10px;
                        border:1px solid #dc2626;
                    ">
                        <h3>Ingestion Errors</h3>

                        <div id="ingestion-errors-box" style="
                            margin-top:15px;
                            display:flex;
                            flex-direction:column;
                            gap:12px;
                        ">
                            <div style="opacity:0.7;">Loading errors...</div>
                        </div>
                    </div>
                        <div style="
                            margin-top:20px;
                            background:#020617;
                            padding:15px;
                            border-radius:10px;
                            border:1px solid #334155;
                        ">
                        
                            <h3>Source Health Status</h3>

                            <div id="source-health-box" style="
                                margin-top:15px;
                                display:flex;
                                flex-direction:column;
                                gap:12px;
                            ">
                                <div style="opacity:0.7;">Loading source health...</div>
                            </div>
                        </div>
                        <div style="
                            margin-top:20px;
                            background:#020617;
                            padding:15px;
                            border-radius:10px;
                            border:1px solid #334155;
                        ">
                            <div style="
                                margin-top:20px;
                                display:grid;
                                grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
                                gap:12px;
                                ">

                                <div style="
                                background:#450a0a;
                                padding:12px;
                                border-radius:10px;
                                border:1px solid #dc2626;
                                ">
                                <div style="font-size:12px;">Open Incidents</div>
                                <div id="open-incidents"
                                style="font-size:24px;font-weight:bold;">
                                0
                                </div>
                                </div>

                                <div style="
                                background:#422006;
                                padding:12px;
                                border-radius:10px;
                                border:1px solid #ca8a04;
                                ">
                                <div style="font-size:12px;">Critical Open</div>
                                <div id="critical-open-incidents"
                                style="font-size:24px;font-weight:bold;">
                                0
                                </div>
                                </div>

                                <div style="
                                background:#052e16;
                                padding:12px;
                                border-radius:10px;
                                border:1px solid #22c55e;
                                ">
                                <div style="font-size:12px;">Resolved</div>
                                <div id="resolved-incidents"
                                style="font-size:24px;font-weight:bold;">
                                0
                                </div>
                                </div>

                                </div>
                                
                            <div style="
                                margin-top:20px;
                                background:#020617;
                                padding:15px;
                                border-radius:10px;
                                border:1px solid #334155;
                            ">
                                <h3>SOC Incident Queue</h3>

                                <div style="
                                    margin-top:12px;
                                    display:flex;
                                    gap:10px;
                                    flex-wrap:wrap;
                                ">
                                    <button onclick="setIncidentFilter('all')" style="
                                        width:auto;
                                        padding:8px 12px;
                                        border-radius:8px;
                                        border:none;
                                        background:#334155;
                                        color:white;
                                        font-weight:bold;
                                        cursor:pointer;
                                    ">
                                        All
                                    </button>

                                    <button onclick="setIncidentFilter('open')" style="
                                        width:auto;
                                        padding:8px 12px;
                                        border-radius:8px;
                                        border:none;
                                        background:#1d4ed8;
                                        color:white;
                                        font-weight:bold;
                                        cursor:pointer;
                                    ">
                                        Open
                                    </button>

                                    <button onclick="setIncidentFilter('acknowledged')" style="
                                        width:auto;
                                        padding:8px 12px;
                                        border-radius:8px;
                                        border:none;
                                        background:#ca8a04;
                                        color:white;
                                        font-weight:bold;
                                        cursor:pointer;
                                    ">
                                        Acknowledged
                                    </button>

                                    <button onclick="setIncidentFilter('critical')" style="
                                        width:auto;
                                        padding:8px 12px;
                                        border-radius:8px;
                                        border:none;
                                        background:#dc2626;
                                        color:white;
                                        font-weight:bold;
                                        cursor:pointer;
                                    ">
                                        Critical
                                    </button>

                                    <button onclick="setIncidentFilter('resolved')" style="
                                        width:auto;
                                        padding:8px 12px;
                                        border-radius:8px;
                                        border:none;
                                        background:#16a34a;
                                        color:white;
                                        font-weight:bold;
                                        cursor:pointer;
                                    ">
                                        Resolved
                                    </button>
                                </div>

                                <div id="incident-queue-box" style="
                                    margin-top:15px;
                                    display:flex;
                                    flex-direction:column;
                                    gap:12px;
                                ">
                                    <div style="opacity:0.7;">Loading incident queue...</div>
                                </div>
                            </div>

                            <div style="
                                margin-top:20px;
                                background:#052e16;
                                padding:15px;
                                border-radius:10px;
                                border:1px solid #22c55e;
                            ">
                                <h3>Resolved Incident History</h3>

                                <div id="resolved-incident-history-box" style="
                                    margin-top:15px;
                                    display:flex;
                                    flex-direction:column;
                                    gap:12px;
                                ">
                                    <div style="opacity:0.7;">Loading resolved incidents...</div>
                                </div>
                            </div>

                            <h3>Source Trend Analytics</h3>
                            <div id="source-uptime-warning" style="
                                display:none;
                                margin-top:12px;
                                padding:12px;
                                border-radius:10px;
                                background:#431407;
                                border:1px solid #f97316;
                                color:#fed7aa;
                                font-weight:bold;
                            ">
                                Source uptime warning
                            </div>
                            <div id="source-risk-warning" style="
                                display:none;
                                margin-top:12px;
                                padding:12px;
                                border-radius:10px;
                                background:#450a0a;
                                border:1px solid #dc2626;
                                color:#fecaca;
                                font-weight:bold;
                            ">
                                Source risk warning
                            </div>
                            <div style="
                                display:grid;
                                grid-template-columns:repeat(auto-fit, minmax(160px, 1fr));
                                gap:12px;
                                margin-top:15px;
                            ">
                                <div style="background:#450a0a; padding:12px; border-radius:10px; border:1px solid #dc2626;">
                                    <div style="color:#fecaca; font-size:12px;">Critical Escalations</div>
                                    <div id="critical-escalations" style="font-size:24px; font-weight:bold;">0</div>
                                </div>

                                <div style="background:#431407; padding:12px; border-radius:10px; border:1px solid #ea580c;">
                                    <div style="color:#fed7aa; font-size:12px;">Spike Alerts</div>
                                    <div id="spike-alerts" style="font-size:24px; font-weight:bold;">0</div>
                                </div>

                                <div style="background:#422006; padding:12px; border-radius:10px; border:1px solid #ca8a04;">
                                    <div style="color:#fef3c7; font-size:12px;">Elevated Sources</div>
                                    <div id="elevated-sources" style="font-size:24px; font-weight:bold;">0</div>
                                </div>

                                <div style="background:#052e16; padding:12px; border-radius:10px; border:1px solid #22c55e;">
                                    <div style="color:#bbf7d0; font-size:12px;">Normal Sources</div>
                                    <div id="normal-sources" style="font-size:24px; font-weight:bold;">0</div>
                                </div>
                            </div>

                            <div id="source-trend-box" style="
                                margin-top:15px;
                                display:flex;
                                flex-direction:column;
                                gap:12px;
                            ">
                                <div style="opacity:0.7;">Loading source trends...</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
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
        function copyPowerShellExample() {
    const example = `$headers = @{
  "Content-Type" = "application/json"
  "X-API-Key" = "YOUR_API_KEY"
}

$body = @{
  event = "Failed login attempt"
  source = "external-firewall"
  ip = "203.0.113.45"
  severity = "high"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://ai-cybersecurity-platform-production.up.railway.app/webhook/log-api-key" -Method POST -Headers $headers -Body $body`;

    navigator.clipboard.writeText(example);
    alert("PowerShell example copied!");
}

        function copyWebhookExample() {
            const example = `POST /webhook/log-api-key

Headers:
Content-Type: application/json
X-API-Key: YOUR_API_KEY

Body:
{
  "event": "Failed login attempt",
  "source": "external-firewall",
  "ip": "203.0.113.45",
  "severity": "high"
}`;

    navigator.clipboard.writeText(example);
    alert("Example copied!");
}

        let fullApiKey = "";
        let apiKeyVisible = false;

        function copyCurlExample() {
    const example = `curl -X POST "https://ai-cybersecurity-platform-production.up.railway.app/webhook/log-api-key" \\
-H "Content-Type: application/json" \\
-H "X-API-Key: YOUR_API_KEY" \\
-d "{\\"event\\":\\"Failed login attempt\\",\\"source\\":\\"external-firewall\\",\\"ip\\":\\"203.0.113.45\\",\\"severity\\":\\"high\\"}"`;

    navigator.clipboard.writeText(example);
    alert("curl example copied!");
}

        async function openAdminDashboard() {
            const token = localStorage.getItem("token");

            const response = await fetch("/admin-dashboard", {
                headers: {
                    "Authorization": "Bearer " + token
                }
            });

            if (!response.ok) {
                alert("Admin access failed");
                return;
            }

            const html = await response.text();

            const newWindow = window.open("", "_blank");
            newWindow.document.write(html);
            newWindow.document.close();
        }

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

                if (billing.remaining <= 3 && billing.plan !== "pro") {
                    document.getElementById("usage-text").innerHTML += 
                        " ⚠️ <span style='color:#f87171; font-weight:bold;'>Almost at daily limit</span>";
                }

            if (billing.plan === "pro") {
                document.getElementById("pro-badge").innerHTML =
                    `<span style="color:#22c55e; font-weight:bold; margin-left:10px;">PRO ✓</span>`;

                document.getElementById("upgrade-section").innerHTML = `
                    <div style="color:#22c55e; font-weight:bold; margin-bottom:10px;">
                        You are on Pro.
                    </div>

                    <button onclick="downgradePlan()" style="
                        background:#64748b;
                        color:white;
                        padding:12px;
                        border:none;
                        border-radius:8px;
                        font-weight:bold;
                        cursor:pointer;
                    ">
                        Downgrade to Free
                    </button>
                `;
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

                let parsedResult = {};

                try {
                    parsedResult = JSON.parse(log.result);
                } catch (e) {
                    parsedResult = {};
                }

                const detailsId = "details-" + log.id;

                item.innerHTML = `
                    <strong>Log:</strong> ${log.raw_log}<br>

                    <strong>Source:</strong>
                    <span style="
                        background:#0f172a;
                        color:#38bdf8;
                        padding:3px 8px;
                        border-radius:999px;
                        font-size:12px;
                        font-weight:bold;
                        border:1px solid #38bdf8;
                    ">
                        ${(parsedResult.source || "manual").toUpperCase()}
                    </span>

                    <br>

                    <strong>Severity:</strong>
                    ${(parsedResult.severity || "LOW").toUpperCase()}

                    <br>

                    <strong>Threat Score:</strong>
                    ${parsedResult.threat_score || 0}

                    <br><br>

                    <button type="button" onclick="toggleLogDetails('${detailsId}')">
                        View Details
                    </button>

                    <div id="${detailsId}" style="display:${openLogDetails.has(detailsId) ? "block" : "none"};margin-top:15px;">
                    <strong>Ingestion:</strong> 
                    <span style="
                        background:${parsedResult.ingestion_method === "api_key_webhook" ? "#22c55e" : "#64748b"};
                        color:white;
                        padding:3px 8px;
                        border-radius:999px;
                        font-size:12px;
                        font-weight:bold;
                    ">
                        ${parsedResult.ingestion_method === "api_key_webhook" ? "API WEBHOOK" : "MANUAL"}
                    </span><br>
                    <strong>Received:</strong> ${parsedResult.received_at || log.created_at}<br>
                    <strong>Anomaly:</strong> ${parsedResult.anomaly === true ? "YES" : "NO"}<br>
                    <strong>Attack Type:</strong> ${parsedResult.attack_type || "unknown"}<br><strong>Severity:</strong>
                    <span style="
                        background:
                            ${(parsedResult.severity || "").toLowerCase() === "critical" ? "#dc2626" :
                            (parsedResult.severity || "").toLowerCase() === "high" ? "#ea580c" :
                            (parsedResult.severity || "").toLowerCase() === "medium" ? "#ca8a04" :
                            "#475569"};
                        color:white;
                        padding:3px 8px;
                        border-radius:999px;
                        font-size:12px;
                        font-weight:bold;
                    ">
                        ${(parsedResult.severity || "low").toUpperCase()}
                    </span><br>
                    <strong>Analysis:</strong> ${parsedResult.analysis || parsedResult.ai_analysis || "No analysis available"}

                    <br><br>

                    <div style="
                        background:#020617;
                        border:1px solid #334155;
                        border-radius:10px;
                        padding:12px;
                        margin-top:12px;
                    ">
                        <div style="
                            color:#38bdf8;
                            font-weight:bold;
                            margin-bottom:10px;
                        ">
                            AI Threat Intelligence
                        </div>

                        <div>
                            <strong>AI Attack Type:</strong>
                            ${parsedResult.ai_attack_type || "Unknown"}
                        </div>

                        <div style="margin-top:6px;">
                            <strong>AI Severity:</strong>
                            <span style="
                                color:
                                    ${(parsedResult.ai_severity || "").toLowerCase() === "critical" ? "#ef4444" :
                                    (parsedResult.ai_severity || "").toLowerCase() === "high" ? "#f97316" :
                                    (parsedResult.ai_severity || "").toLowerCase() === "medium" ? "#eab308" :
                                    "#22c55e"};
                                font-weight:bold;
                            ">
                                ${(parsedResult.ai_severity || "LOW").toUpperCase()}
                            </span>
                        </div>

                        <div style="margin-top:6px;">
                            <strong>Threat Sophistication:</strong>
                            ${parsedResult.threat_intelligence?.threat_actor_sophistication || "Unknown"}
                        </div>

                        <div style="margin-top:6px;">
                            <strong>Incident Urgency:</strong>
                            ${parsedResult.threat_intelligence?.incident_urgency || "Unknown"}
                        </div>

                        <div style="margin-top:10px;">
                            <strong>Recommended Actions:</strong>
                            <ul style="margin-top:6px;">
                                ${
                                    parsedResult.threat_intelligence?.recommended_actions?.map(action =>
                                        `<li>${action}</li>`
                                    ).join("") || "<li>No actions available</li>"
                                }
                            </ul>
                        </div>

                        <div style="margin-top:10px;">
                            <strong>Correlation Summary:</strong>
                            <div style="margin-top:6px;">
                                Total Incidents:
                                ${parsedResult.correlation_analysis?.total_incidents || 0}
                            </div>

                            <div style="margin-top:6px;">
                                Campaign Detected:
                                ${
                                    parsedResult.correlation_analysis?.campaign_analysis?.campaign_detected
                                        ? "YES"
                                        : "NO"
                                }
                            </div>

                            <div style="margin-top:6px;">
                                Mixed Attack Behavior:
                                ${
                                    parsedResult.correlation_analysis?.mixed_attack_behavior?.mixed_attack_detected
                                        ? "YES"
                                        : "NO"
                                }
                            </div>
                        </div>

                        <div style="margin-top:10px;">
                            <strong>Timeline Intelligence:</strong>

                            <div style="margin-top:6px;">
                                Total Events:
                                ${parsedResult.timeline_intelligence?.total_events || 0}
                            </div>

                            <div style="margin-top:6px;">
                                Attack Types:
                                ${parsedResult.timeline_intelligence?.unique_attack_types || 0}
                            </div>

                            <div style="margin-top:6px;">
                                Escalation Level:
                                ${
                                    parsedResult.timeline_intelligence?.escalation_level || "low"
                                }
                            </div>
                        </div>

                        <div style="margin-top:10px;">
                            <strong>Behavior Profile:</strong>

                            <div style="margin-top:6px;">
                                Behavior Type:
                                ${
                                    parsedResult.behavior_profile?.behavior_type ||
                                    "unknown"
                                }
                            </div>

                            <div style="margin-top:6px;">
                                Persistence:
                                ${
                                    parsedResult.behavior_profile?.persistence_level ||
                                    "low"
                                }
                            </div>

                            <div style="margin-top:10px;">
                                <strong>Risk Classification:</strong>

                                <div style="margin-top:6px;">
                                    Classification:
                                    ${
                                        parsedResult.risk_classification?.risk_classification ||
                                        "Low Risk"
                                    }
                                </div>

                                <div style="margin-top:6px;">
                                    Risk Score:
                                    ${
                                        parsedResult.risk_classification?.risk_score || 0
                                    }
                                </div>

                                <div style="margin-top:6px;">
                                    Analyst Priority:
                                    ${
                                        parsedResult.risk_classification?.analyst_priority ||
                                        "Low"
                                    }
                                </div>
                            </div>

                            <div style="margin-top:10px;">
                                <strong>Campaign Attribution:</strong>

                                <div style="margin-top:6px;">
                                    Campaign Detected:
                                    ${
                                        parsedResult.campaign_attribution?.campaign_detected
                                            ? "YES"
                                            : "NO"
                                    }
                                </div>

                                <div style="margin-top:10px;">
                                    <strong>Escalation Prediction:</strong>

                                    <div style="margin-top:6px;">
                                        Escalation Likely:
                                        ${
                                            parsedResult.escalation_prediction?.escalation_likely
                                                ? "YES"
                                                : "NO"
                                        }
                                    </div>

                                    <div style="margin-top:6px;">
                                        Predicted Stage:
                                        ${
                                            parsedResult.escalation_prediction?.predicted_stage ||
                                            "stable"
                                        }
                                    </div>

                                    <div style="margin-top:6px;">
                                        Confidence:
                                        ${
                                            parsedResult.escalation_prediction?.prediction_confidence || 0
                                        }%
                                    </div>
                                </div>

                                <div style="margin-top:10px;">
                                    <strong>Threat Hunting Recommendations:</strong>

                                    <div style="margin-top:6px;">
                                        Recommendation:
                                        ${
                                            parsedResult.hunting_recommendations?.hunt_recommendation ||
                                            "Continue monitoring"
                                        }
                                    </div>

                                    <div style="margin-top:6px;">
                                        Priority:
                                        ${
                                            parsedResult.hunting_recommendations?.priority ||
                                            "low"
                                        }
                                    </div>

                                    <div style="margin-top:6px;">
                                        Confidence:
                                        ${
                                            parsedResult.hunting_recommendations?.confidence || 0
                                        }%
                                    </div>
                                </div>

                                <div style="margin-top:10px;">
                                    <strong>Threat Actor Confidence:</strong>

                                    <div style="margin-top:6px;">
                                        Confidence Score:
                                        ${
                                            parsedResult.actor_confidence?.actor_confidence || 0
                                        }
                                    </div>

                                    <div style="margin-top:6px;">
                                        Confidence Level:
                                        ${
                                            parsedResult.actor_confidence?.confidence_level ||
                                            "Low"
                                        }
                                    </div>

                                    <div style="margin-top:10px;">
                                        <strong>Executive Summary:</strong>

                                        <div style="margin-top:6px;">
                                            Assessment:
                                            ${
                                                parsedResult.executive_summary?.executive_assessment ||
                                                "Limited evidence"
                                            }
                                        </div>

                                        <div style="margin-top:6px;">
                                            Threat Level:
                                            ${
                                                parsedResult.executive_summary?.threat_level ||
                                                "LOW"
                                            }
                                        </div>

                                        <div style="margin-top:6px;">
                                            Recommended Action:
                                            ${
                                                parsedResult.executive_summary?.recommended_action ||
                                                "Continue monitoring"
                                            }
                                        </div>

                                        <div style="margin-top:6px;">
                                            Analyst Confidence:
                                            ${
                                                parsedResult.executive_summary?.analyst_confidence || 0
                                            }
                                        </div>
                                    </div>

                                    <div style="margin-top:10px;">
                                        <strong>MITRE ATT&CK Mapping:</strong>

                                        <div style="margin-top:6px;">
                                            Technique ID:
                                            ${
                                                parsedResult.mitre_mapping?.mitre_technique_id ||
                                                "T0000"
                                            }
                                        </div>

                                        <div style="margin-top:6px;">
                                            Technique:
                                            ${
                                                parsedResult.mitre_mapping?.mitre_technique_name ||
                                                "Unknown Technique"
                                            }
                                        </div>

                                        <div style="margin-top:6px;">
                                            Tactic:
                                            ${
                                                parsedResult.mitre_mapping?.mitre_tactic ||
                                                "Unknown"
                                            }
                                        </div>

                                        <div style="margin-top:6px;">
                                            Severity:
                                            ${
                                                parsedResult.mitre_mapping?.mitre_severity ||
                                                "low"
                                            }
                                        </div>
                                    </div>

                                    <div style="margin-top:10px;">
                                        <strong>IOC Intelligence:</strong>

                                        <div style="margin-top:6px;">
                                            IOC Count:
                                            ${
                                                parsedResult.ioc_data?.ioc_count || 0
                                            }
                                        </div>

                                        <div style="margin-top:6px;">
                                            Indicators:
                                            ${
                                                parsedResult.ioc_data?.iocs
                                                    ?.map(ioc => `${ioc.indicator_type}: ${ioc.indicator_value}`)
                                                    .join(", ")
                                                || "None Detected"
                                            }
                                        </div>
                                    </div>

                                    <div style="margin-top:10px;">
                                        <strong>Threat Actor Fingerprint:</strong>

                                        <div style="margin-top:6px;">
                                            Fingerprint ID:
                                            ${
                                                parsedResult.threat_fingerprint?.fingerprint_id ||
                                                "unknown"
                                            }
                                        </div>

                                        <div style="margin-top:6px;">
                                            Repeat Offender:
                                            ${
                                                parsedResult.threat_fingerprint?.repeat_offender
                                                    ? "Yes"
                                                    : "No"
                                            }
                                        </div>

                                        <div style="margin-top:6px;">
                                            Attack Pattern:
                                            ${
                                                parsedResult.threat_fingerprint?.attack_pattern ||
                                                "unknown_activity"
                                            }
                                        </div>

                                        <div style="margin-top:6px;">
                                            Aggression Level:
                                            ${
                                                parsedResult.threat_fingerprint?.aggression_level ||
                                                "low"
                                            }
                                        </div>

                                        <div style="margin-top:6px;">
                                            Risk Classification:
                                            ${
                                                parsedResult.threat_fingerprint?.risk_classification ||
                                                "low_risk"
                                            }
                                        </div>
                                    </div>

                                    <div style="margin-top:10px;">
                                        <strong>Threat Cluster Detection:</strong>

                                        <div style="margin-top:6px;">
                                            Cluster Name:
                                            ${
                                                parsedResult.threat_cluster?.cluster_name ||
                                                "unknown_cluster"
                                            }
                                        </div>

                                        <div style="margin-top:6px;">
                                            Cluster Confidence:
                                            ${
                                                parsedResult.threat_cluster?.cluster_confidence || 0
                                            }%
                                        </div>

                                        <div style="margin-top:6px;">
                                            Related Incidents:
                                            ${
                                                parsedResult.threat_cluster?.related_incidents || 0
                                            }
                                        </div>

                                        <div style="margin-top:6px;">
                                            Active Cluster:
                                            ${
                                                parsedResult.threat_cluster?.cluster_active
                                                    ? "YES"
                                                    : "NO"
                                            }
                                        </div>
                                    </div>

                                    <div style="margin-top:10px;">
                                        <strong>Threat Reputation:</strong>

                                        <div style="margin-top:6px;">
                                            Reputation Score:
                                            ${
                                                parsedResult.threat_reputation?.reputation_score || 0
                                            }
                                        </div>

                                        <div style="margin-top:6px;">
                                            Reputation Level:
                                            ${
                                                parsedResult.threat_reputation?.reputation_level ||
                                                "low"
                                            }
                                        </div>
                                    </div>

                                    <div style="margin-top:10px;">
                                        <strong>IOC Enrichment:</strong>

                                        <div style="margin-top:6px;">
                                            Enriched IOC Count:
                                            ${
                                                parsedResult.ioc_enrichment?.ioc_count || 0
                                            }
                                        </div>

                                        <div style="margin-top:6px;">
                                            Indicators:
                                            ${
                                                parsedResult.ioc_enrichment?.enriched_iocs
                                                    ?.map(ioc =>
                                                        `${ioc.indicator_value} (${ioc.risk_level})`
                                                    )
                                                    .join(", ")
                                                || "None"
                                            }
                                        </div>
                                    </div>

                                    <div style="margin-top:10px;">
                                        <strong>Threat Narrative:</strong>

                                        <div style="
                                            margin-top:8px;
                                            padding:10px;
                                            background:#020617;
                                            border:1px solid #334155;
                                            border-radius:8px;
                                            line-height:1.5;
                                        ">
                                            ${
                                                parsedResult.threat_narrative?.narrative ||
                                                "No narrative generated"
                                            }
                                        </div>
                                    </div>

                                    <div style="margin-top:10px;">
                                        <strong>Intelligence Rollup:</strong>

                                        <div style="
                                            margin-top:8px;
                                            padding:10px;
                                            background:#020617;
                                            border:1px solid #334155;
                                            border-radius:8px;
                                        ">
                                            <div>
                                                Overall Risk:
                                                ${
                                                    parsedResult.intelligence_rollup?.overall_risk ||
                                                    "low_risk"
                                                }
                                            </div>

                                            <div style="margin-top:6px;">
                                                Reputation:
                                                ${
                                                    parsedResult.intelligence_rollup?.reputation_level ||
                                                    "low"
                                                }
                                            </div>

                                            <div style="margin-top:6px;">
                                                Cluster:
                                                ${
                                                    parsedResult.intelligence_rollup?.cluster_name ||
                                                    "unknown_cluster"
                                                }
                                            </div>

                                            <div style="margin-top:6px;">
                                                MITRE:
                                                ${
                                                    parsedResult.intelligence_rollup?.mitre_technique ||
                                                    "Unknown Technique"
                                                }
                                            </div>

                                            <div style="margin-top:6px;">
                                                IOC Count:
                                                ${
                                                    parsedResult.intelligence_rollup?.ioc_count || 0
                                                }
                                            </div>

                                            <div style="margin-top:10px;">
                                                <strong>Executive Narrative:</strong>
                                            </div>

                                            <div style="margin-top:6px;">
                                                ${
                                                    parsedResult.intelligence_rollup?.executive_narrative ||
                                                    "No narrative available"
                                                }
                                            </div>
                                        </div>
                                    </div>

                                    <div style="margin-top:6px;">
                                        Analyst Assessment:
                                        ${
                                            parsedResult.actor_confidence?.analyst_assessment ||
                                            "Limited evidence"
                                        }
                                    </div>
                                </div>

                                <div style="margin-top:6px;">
                                    Campaign Name:
                                    ${
                                        parsedResult.campaign_attribution?.campaign_name ||
                                        "Unknown Activity"
                                    }
                                </div>

                                <div style="margin-top:6px;">
                                    Confidence:
                                    ${
                                        parsedResult.campaign_attribution?.campaign_confidence || 0
                                    }%
                                </div>

                                <div style="margin-top:6px;">
                                    Latest Attack:
                                    ${
                                        parsedResult.campaign_attribution?.latest_attack_type ||
                                        "unknown"
                                    }
                                </div>
                            </div>

                            <div style="margin-top:6px;">
                                Aggression:
                                ${
                                    parsedResult.behavior_profile?.aggression_level ||
                                    "low"
                                }
                            </div>

                            <div style="margin-top:6px;">
                                Repeat Offender:
                                ${
                                    parsedResult.behavior_profile?.repeat_offender
                                        ? "YES"
                                        : "NO"
                                }
                            </div>

                            <div style="margin-top:6px;">
                                Confidence:
                                ${
                                    parsedResult.behavior_profile?.confidence || 0
                                }%
                            </div>
                        </div>

                    </div>

                    <br>
                    </div>

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

        let openLogDetails = new Set();

        function toggleLogDetails(id) {
            const el = document.getElementById(id);

            if (!el) return;

            if (el.style.display === "none") {
                el.style.display = "block";
                openLogDetails.add(id);
            } else {
                el.style.display = "none";
                openLogDetails.delete(id);
            }
        }

        let socket;

        function formatRelativeTime(timestamp) {
            if (!timestamp) return "unknown";

            const then = new Date(timestamp);
            const now = new Date();
            const diffSeconds = Math.floor((now - then) / 1000);

            if (diffSeconds < 60) return `${diffSeconds}s ago`;
            if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)}m ago`;
            if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)}h ago`;

            return `${Math.floor(diffSeconds / 86400)}d ago`;
        }

        function connectWebSocket() {
            const protocol = window.location.protocol === "https:" ? "wss://" : "ws://";
            const wsUrl = protocol + window.location.host + "/ws/logs";

            socket = new WebSocket(wsUrl);

            socket.onopen = () => {
                console.log("WebSocket connected");
            };

            socket.onmessage = async (event) => {
                const data = JSON.parse(event.data);

                if (data.type === "new_log") {
                    console.log("New log received:", data.log);

                    await loadSourceAnalytics();
                    await loadIngestionActivity();
                    await loadIngestionErrors();
                    await loadIncidentSummary();
                    await loadIncidentQueue();
                    await loadResolvedIncidentHistory();
                }
            };

            socket.onclose = () => {
                console.log("WebSocket disconnected, reconnecting...");
                setTimeout(connectWebSocket, 3000);
            };
        }

        async function loadSourceAnalytics() {
            const token = localStorage.getItem("token");

            let data = {};

            try {
                const response = await fetch("/source-analytics", {
                    headers: {
                        "Authorization": "Bearer " + token
                    }
                });

                if (!response.ok) {
                    throw new Error("Source analytics request failed");
                }

                data = await response.json();
            } catch (error) {
                console.error("Source analytics error:", error);

                document.getElementById("logs-today").innerText = "Error";
                document.getElementById("total-sources").innerText = "Error";
                document.getElementById("top-source").innerText = "Unavailable";
                document.getElementById("source-trend-box").innerHTML =
                    "<div style='color:#f87171;'>Could not load source analytics.</div>";

                return;
            }
            const sources = data.sources || {};

            const entries = Object.entries(sources);

            document.getElementById("total-sources").innerText = data.total_sources || 0;
            document.getElementById("logs-today").innerText = data.logs_today || 0;
            document.getElementById("top-source").innerText =
                data.top_source ? `${data.top_source} (${data.top_source_count} logs)` : "None";

            entries.sort((a, b) => b[1] - a[1]);
            const noisySources = data.noisy_sources || [];
            const suspiciousSources = data.suspicious_sources || [];

            document.getElementById("noisy-count").innerText = noisySources.length;
            document.getElementById("suspicious-count").innerText = suspiciousSources.length;
            const sourceList = document.getElementById("source-list");
            sourceList.innerHTML = "";

            entries.forEach(([source, count]) => {
                const item = document.createElement("div");
                item.style.padding = "8px";
                item.style.marginTop = "8px";
                item.style.background = "#1e293b";
                item.style.borderRadius = "8px";
                item.innerText = `${source}: ${count} logs`;
                sourceList.appendChild(item);
            });

            const noisyBox = document.getElementById("noisy-sources-box");
            noisyBox.innerHTML = "<h4>Noisy Sources</h4>";

            if (!noisySources.length) {
                noisyBox.innerHTML += "<div>No noisy sources detected</div>";
            } else {
                noisySources.forEach(source => {
                    noisyBox.innerHTML += `
                        <div style="margin-top:8px;">
                            <strong>${source.source}</strong>
                            — ${source.count} logs
                        </div>
                    `;
                });
            }

            const suspiciousBox = document.getElementById("suspicious-sources-box");
            suspiciousBox.innerHTML = "<h4>Suspicious Sources</h4>";

            if (!suspiciousSources.length) {
                suspiciousBox.innerHTML += "<div>No suspicious sources detected</div>";
            } else {
                suspiciousSources.forEach(source => {
                    suspiciousBox.innerHTML += `
                        <div style="
                            margin-top:10px;
                            padding:12px;
                            background:#312e81;
                            border-radius:10px;
                            border:1px solid #7c3aed;
                        ">
                            <div style="
                                display:flex;
                                justify-content:space-between;
                                align-items:center;
                                margin-bottom:8px;
                            ">
                                <strong>${source.source}</strong>

                                <span style="
                                    background:
                                        ${source.risk_level === "critical" ? "#dc2626" :
                                        source.risk_level === "high" ? "#ea580c" :
                                        "#ca8a04"};
                                    color:white;
                                    padding:4px 10px;
                                    border-radius:999px;
                                    font-size:12px;
                                    font-weight:bold;
                                ">
                                    ${(source.risk_level || "medium").toUpperCase()}
                                </span>
                            </div>

                            <div>Score: ${source.score}</div>
                            <div style="margin-top:6px; opacity:0.9;">
                                ${source.reason}
                            </div>
                        </div>
                    `;
                });
            }
            const healthBox = document.getElementById("source-health-box");
            const healthSources = data.source_health || [];
            const uptimeWarningBox = document.getElementById("source-uptime-warning");
            const riskWarningBox = document.getElementById("source-risk-warning");

            const staleOrInactiveSources = healthSources.filter(source =>
                source.uptime_status === "stale" || source.uptime_status === "inactive"
            );

            if (uptimeWarningBox) {
                if (staleOrInactiveSources.length > 0) {
                    uptimeWarningBox.style.display = "block";
                    uptimeWarningBox.innerText =
                        `⚠️ ${staleOrInactiveSources.length} source(s) are stale or inactive`;
                } else {
                    uptimeWarningBox.style.display = "none";
                }
            }

            const highRiskSources = healthSources.filter(source =>
                source.escalation_level === "high" || source.escalation_level === "critical"
            );

            if (riskWarningBox) {
                if (highRiskSources.length > 0) {
                    riskWarningBox.style.display = "block";
                    riskWarningBox.innerText =
                        `🚨 ${highRiskSources.length} source(s) have high or critical risk escalation`;
                } else {
                    riskWarningBox.style.display = "none";
                }
            }

            const criticalEscalations = healthSources.filter(s => s.escalation_level === "critical").length;
            const spikeAlerts = healthSources.filter(s => s.spike_detected === true).length;
            const elevatedSources = healthSources.filter(s => s.escalation_level === "elevated").length;
            const normalSources = healthSources.filter(s => s.escalation_level === "normal").length;

            document.getElementById("critical-escalations").innerText = criticalEscalations;
            document.getElementById("spike-alerts").innerText = spikeAlerts;
            document.getElementById("elevated-sources").innerText = elevatedSources;
            document.getElementById("normal-sources").innerText = normalSources;
            const trendBox = document.getElementById("source-trend-box");

            if (healthBox) {
                healthBox.innerHTML = "";

                if (!healthSources.length) {
                    healthBox.innerHTML = "<div>No source health data yet</div>";
                } else {
                    healthSources.forEach(source => {
                        const item = document.createElement("div");

                        let statusColor = "#22c55e";

                        if (source.status === "degraded") {
                            statusColor = "#ca8a04";
                        }

                        if (source.status === "suspicious" || source.status === "offline") {
                            statusColor = "#dc2626";
                        }

                        item.style.background = "#0f172a";
                        item.style.padding = "12px";
                        item.style.borderRadius = "10px";
                        item.style.border = "1px solid #334155";

                        item.innerHTML = `
                            <div style="
                                display:flex;
                                justify-content:space-between;
                                align-items:center;
                            ">
                                <strong>${source.source}</strong>

                                <span style="
                                    background:${statusColor};
                                    color:white;
                                    padding:4px 10px;
                                    border-radius:999px;
                                    font-size:12px;
                                    font-weight:bold;
                                ">
                                    ${(source.status || "healthy").toUpperCase()}
                                </span>
                            </div>

                            <small style="opacity:0.7;">
                                ${source.count} logs processed
                            </small>
                        `;

                        healthBox.appendChild(item);
                    });
                }
            
        }

        if (trendBox) {
                trendBox.innerHTML = "";

                if (!healthSources.length) {
                    trendBox.innerHTML = "<div>No source trend data yet</div>";
                } else {
                    healthSources.forEach(source => {
                        const item = document.createElement("div");

                        let escalationColor = "#22c55e";

                        if (source.escalation_level === "elevated") {
                            escalationColor = "#ca8a04";
                        }

                        if (source.escalation_level === "high") {
                            escalationColor = "#ea580c";
                        }

                        if (source.escalation_level === "critical") {
                            escalationColor = "#dc2626";
                        }

                        let cardBackground = "#0f172a";

                        if (source.uptime_status === "stale") {
                            cardBackground = "#1f1a0a";
                        }

                        if (source.uptime_status === "inactive") {
                            cardBackground = "#2a0f0f";
                        }

                        item.style.background = cardBackground;
                        item.style.padding = "12px";
                        item.style.borderRadius = "10px";
                        item.style.border = `1px solid ${escalationColor}`;

                        if (source.uptime_status === "inactive") {
                            item.style.boxShadow = "0 0 14px rgba(220, 38, 38, 0.35)";
                        } else if (source.uptime_status === "stale") {
                            item.style.boxShadow = "0 0 12px rgba(202, 138, 4, 0.25)";
                        } else {
                            item.style.boxShadow = "none";
                        }

                        item.innerHTML = `
                            <div style="
                                display:flex;
                                justify-content:space-between;
                                align-items:center;
                                margin-bottom:8px;
                            ">
                                <div style="display:flex; align-items:center; gap:8px;">
                                    <span style="
                                        width:10px;
                                        height:10px;
                                        border-radius:999px;
                                        display:inline-block;
                                        background:${
                                            source.uptime_status === "active" ? "#22c55e" :
                                            source.uptime_status === "stale" ? "#ca8a04" :
                                            source.uptime_status === "inactive" ? "#dc2626" :
                                            "#94a3b8"
                                        };
                                        box-shadow:${
                                            source.uptime_status === "active" ? "0 0 10px #22c55e" :
                                            source.uptime_status === "stale" ? "0 0 10px #ca8a04" :
                                            source.uptime_status === "inactive" ? "0 0 10px #dc2626" :
                                            "none"
                                        };

                                        animation:${
                                            source.uptime_status === "active" ? "heartbeatPulse 1.5s infinite" :
                                            "none"
                                        };

                                    "></span>

                                    <strong>${source.source}</strong>
                                </div>

                                <span style="
                                    background:${escalationColor};
                                    color:white;
                                    padding:4px 10px;
                                    border-radius:999px;
                                    font-size:12px;
                                    font-weight:bold;
                                ">
                                    ${
                                        source.escalation_level === "critical" ? "CRITICAL RESPONSE" :
                                        source.escalation_level === "high" ? "HIGH PRIORITY" :
                                        source.escalation_level === "elevated" ? "ELEVATED WATCH" :
                                        "NORMAL WATCH"
                                    }
                                </span>
                            </div>

                            <div style="font-size:14px; margin-bottom:6px;">
                                Recent Events: <strong>${source.recent_events}</strong> |
                                Older Events: <strong>${source.older_events}</strong>
                            </div>

                            <div style="font-size:14px; margin-bottom:6px;">
                                Growth:
                                <strong style="
                                    color:${
                                        source.growth_percent > 0 ? "#22c55e" :
                                        source.growth_percent < 0 ? "#38bdf8" :
                                        "#94a3b8"
                                    };
                                ">
                                    ${
                                        source.growth_percent > 0 ? "▲" :
                                        source.growth_percent < 0 ? "▼" :
                                        "■"
                                    }
                                    ${source.growth_percent}%
                                </strong>
                            </div>

                            <div style="font-size:14px; margin-bottom:6px;">
                                Last Seen:
                                <strong>
                                    ${formatRelativeTime(source.last_seen)}
                                </strong>
                            </div>

                            <div style="font-size:14px; margin-bottom:6px;">
                                Uptime:
                                <strong style="
                                    color:${
                                        source.uptime_status === "active" ? "#22c55e" :
                                        source.uptime_status === "stale" ? "#ca8a04" :
                                        source.uptime_status === "inactive" ? "#dc2626" :
                                        "#94a3b8"
                                    };
                                ">
                                    ${(source.uptime_status || "unknown").toUpperCase()}
                                </strong>
                            </div>

                            <div style="font-size:13px; margin-bottom:6px; opacity:0.85;">
                                Trend Warning:
                                <strong>
                                    ${
                                        source.spike_detected ? "Sudden activity spike detected" :
                                        source.growth_percent >= 100 ? "Activity doubled compared to previous window" :
                                        source.growth_percent >= 50 ? "Activity rising quickly" :
                                        source.growth_percent <= -50 ? "Activity dropped sharply" :
                                        source.growth_percent > 0 ? "Activity increasing" :
                                        source.growth_percent < 0 ? "Activity decreasing" :
                                        "Activity stable"
                                    }
                                </strong>
                            </div>

                            <div style="font-size:13px; margin-bottom:6px; opacity:0.85;">
                                Risk Reason:
                                <strong>
                                    ${
                                        source.escalation_level === "critical" ? "Critical activity or spike detected" :
                                        source.escalation_level === "high" ? "High suspicious activity score" :
                                        source.escalation_level === "elevated" ? "Growing or noisy source activity" :
                                        "Normal source behavior"
                                    }
                                </strong>
                            </div>

                            <div style="font-size:13px; margin-bottom:6px; opacity:0.85;">
                                Recommended Action:
                                <strong>
                                    ${
                                        source.escalation_level === "critical" ? "Investigate immediately and consider blocking this source" :
                                        source.escalation_level === "high" ? "Review recent activity and monitor closely" :
                                        source.uptime_status === "inactive" ? "Check whether this source stopped sending logs" :
                                        source.uptime_status === "stale" ? "Verify ingestion connection and source heartbeat" :
                                        source.spike_detected ? "Inspect recent spike activity for anomalies" :
                                        "Continue monitoring"
                                    }
                                </strong>
                            </div>

                            ${
                                source.escalation_level === "critical" || source.escalation_level === "high"
                                ? `
                                    <div style="
                                        margin-top:10px;
                                        padding:10px;
                                        border-radius:8px;
                                        background:${
                                            source.escalation_level === "critical"
                                                ? "rgba(220,38,38,0.18)"
                                                : "rgba(234,88,12,0.18)"
                                        };
                                        border:1px solid ${
                                            source.escalation_level === "critical"
                                                ? "#dc2626"
                                                : "#ea580c"
                                        };
                                        color:white;
                                        font-size:13px;
                                        font-weight:bold;
                                    ">
                                        ${
                                            source.escalation_level === "critical"
                                                ? "🚨 Immediate SOC investigation recommended"
                                                : "⚠️ Elevated monitoring recommended"
                                        }
                                    </div>
                                `
                                : ""
                            }

                            <div style="
                                margin-top:10px;
                                padding:10px;
                                border-radius:8px;
                                background:#020617;
                                border:1px solid #334155;
                                font-size:13px;
                                opacity:0.95;
                            ">
                                <strong>Investigation Notes:</strong><br>
                                ${
                                    source.escalation_level === "critical" ? "Check source logs, recent failed attempts, blacklist status, and possible blocking action." :
                                    source.escalation_level === "high" ? "Review recent events, compare activity growth, and verify whether this source is expected." :
                                    source.uptime_status === "inactive" ? "Confirm the source is still online and sending telemetry." :
                                    source.uptime_status === "stale" ? "Check ingestion heartbeat and API/webhook connection." :
                                    source.spike_detected ? "Inspect the spike window and compare it with normal source behavior." :
                                    "No immediate action required. Continue routine monitoring."
                                }
                            </div>

                            <div style="font-size:14px;">
                                Spike Detected:
                                <strong style="color:${source.spike_detected ? "#dc2626" : "#22c55e"};">
                                    ${source.spike_detected ? "YES" : "NO"}
                                </strong>
                            </div>

                            <div style="margin-top:10px; font-size:12px; opacity:0.8;">
                                Source Risk Score
                            </div>

                            <div style="
                                margin-top:6px;
                                height:12px;
                                background:#1e293b;
                                border-radius:999px;
                                overflow:hidden;
                                border:1px solid #334155;
                            ">
                                <div style="
                                    height:100%;
                                    width:${
                                        source.escalation_level === "critical" ? "100%" :
                                        source.escalation_level === "high" ? "75%" :
                                        source.escalation_level === "elevated" ? "50%" :
                                        "20%"
                                    };
                                    background:${
                                        source.escalation_level === "critical" ? "#dc2626" :
                                        source.escalation_level === "high" ? "#ea580c" :
                                        source.escalation_level === "elevated" ? "#ca8a04" :
                                        "#22c55e"
                                    };
                                    transition:width 0.4s ease;
                                "></div>
                            </div>
                            <div style="
                                margin-top:10px;
                                height:10px;
                                background:#1e293b;
                                border-radius:999px;
                                overflow:hidden;
                            ">
                                <div style="
                                    height:100%;
                                    width:${Math.min(Math.abs(source.growth_percent || 0), 100)}%;
                                    background:${escalationColor};
                                    transition:width 0.4s ease;
                                "></div>
                            </div>

                            <div style="
                                margin-top:6px;
                                font-size:12px;
                                opacity:0.7;
                            ">
                                Activity Growth Monitor
                            </div>
                        `;

                        trendBox.appendChild(item);
                    });
                }
            }
        }

        async function loadIngestionActivity() {
            const token = localStorage.getItem("token");

            let data = {};

            try {
                const response = await fetch("/ingestion-activity", {
                    headers: {
                        "Authorization": "Bearer " + token
                    }
                });

                if (!response.ok) {
                    throw new Error("Ingestion activity request failed");
                }

                data = await response.json();
            } catch (error) {
                console.error("Ingestion activity error:", error);

                const box = document.getElementById("ingestion-activity-box");
                if (box) {
                    box.innerHTML =
                        "<div style='color:#f87171;'>Could not load ingestion activity.</div>";
                }

                return;
            }

            const box = document.getElementById("ingestion-activity-box");

            if (!box) return;

            box.innerHTML = "";

            const activity = data.activity || [];

            if (!activity.length) {
                box.innerHTML = "<div>No ingestion activity yet</div>";
                return;
            }

            activity.forEach(item => {
                const row = document.createElement("div");

                let severityColor = "#475569";

                if ((item.severity || "").toLowerCase() === "high") {
                    severityColor = "#dc2626";
                } else if ((item.severity || "").toLowerCase() === "medium") {
                    severityColor = "#ca8a04";
                }

                row.style.background = "#0f172a";
                row.style.padding = "12px";
                row.style.borderRadius = "10px";
                row.style.border = "1px solid #334155";

                row.innerHTML = `
                    <div style="
                        display:flex;
                        justify-content:space-between;
                        align-items:center;
                        margin-bottom:8px;
                    ">
                        <strong>${item.source}</strong>

                        <span style="
                            background:${severityColor};
                            color:white;
                            padding:4px 10px;
                            border-radius:999px;
                            font-size:12px;
                            font-weight:bold;
                        ">
                            ${(item.severity || "LOW").toUpperCase()}
                        </span>
                    </div>

                    <div style="margin-bottom:6px;">
                        ${item.event}
                    </div>

                    <small style="opacity:0.7;">
                        Status: ${item.status} • ${item.timestamp}
                    </small>
                `;

                box.appendChild(row);
            });
        }

        async function loadIngestionErrors() {
            const token = localStorage.getItem("token");

            let data = {};

            try {
                const response = await fetch("/ingestion-errors", {
                    headers: {
                        "Authorization": "Bearer " + token
                    }
                });

                if (!response.ok) {
                    throw new Error("Ingestion errors request failed");
                }

                data = await response.json();
            } catch (error) {
                console.error("Ingestion errors error:", error);

                const box = document.getElementById("ingestion-errors-box");
                if (box) {
                    box.innerHTML =
                        "<div style='color:#fecaca;'>Could not load ingestion errors.</div>";
                }

                return;
            }

            const box = document.getElementById("ingestion-errors-box");
            if (!box) return;

            box.innerHTML = "";

            const errors = data.errors || [];

            if (!errors.length) {
                box.innerHTML = "<div>No ingestion errors detected</div>";
                return;
            }

            errors.forEach(error => {
                const row = document.createElement("div");

                row.style.background = "#7f1d1d";
                row.style.padding = "12px";
                row.style.borderRadius = "10px";
                row.style.border = "1px solid #ef4444";

                row.innerHTML = `
                    <strong>${error.source}</strong><br>
                    <div>${error.error}</div>
                    <small>Status: ${error.status} • ${error.timestamp}</small>
                `;

                box.appendChild(row);
            });
        }

        async function loadIncidentSummary() {
            const token = localStorage.getItem("token");

            try {
                const response = await fetch("/incident-summary", {
                    headers: {
                        "Authorization": "Bearer " + token
                    }
                });

                if (!response.ok) {
                    throw new Error("Incident summary failed");
                }

                const data = await response.json();

                document.getElementById("open-incidents").innerText =
                    data.active_incidents || 0;

                document.getElementById("critical-open-incidents").innerText =
                    data.critical_open_incidents || 0;

                document.getElementById("resolved-incidents").innerText =
                    data.resolved_incidents || 0;

            } catch(error) {
                console.error("Incident summary error:", error);
            }
        }

        let incidentFilter = "all";

        function setIncidentFilter(filter) {
            incidentFilter = filter;
            loadIncidentQueue();
        }

        async function loadIncidentQueue() {
            const token = localStorage.getItem("token");

            try {
                const response = await fetch("/incident-queue", {
                    headers: {
                        "Authorization": "Bearer " + token
                    }
                });

                if (!response.ok) {
                    throw new Error("Incident queue failed");
                }

                const data = await response.json();
                const box = document.getElementById("incident-queue-box");

                if (!box) return;

                box.innerHTML = "";

                let incidents = data.incidents || [];

                incidents.sort((a, b) => {
                    const priority = {
                        critical: 4,
                        high: 3,
                        elevated: 2,
                        normal: 1
                    };

                    return (
                        (priority[b.escalation_level] || 0) -
                        (priority[a.escalation_level] || 0)
                    );
                });

                if (incidentFilter === "open") {
                    incidents = incidents.filter(i =>
                        i.status === "email_pending"
                    );
                }

                if (incidentFilter === "acknowledged") {
                    incidents = incidents.filter(i =>
                        i.status === "acknowledged"
                    );
                }

                if (incidentFilter === "critical") {
                    incidents = incidents.filter(i =>
                        i.escalation_level === "critical"
                    );
                }

                if (incidentFilter === "resolved") {
                    incidents = incidents.filter(i =>
                        i.status === "resolved"
                    );
                }

                if (!incidents.length) {
                    box.innerHTML = "<div>No open incidents</div>";
                    return;
                }

                incidents.forEach(incident => {
                    const row = document.createElement("div");

                    let borderColor = "#334155";
                    let badgeColor = "#64748b";

                    if (incident.escalation_level === "critical") {
                        borderColor = "#dc2626";
                        badgeColor = "#dc2626";
                    } else if (incident.escalation_level === "high") {
                        borderColor = "#ea580c";
                        badgeColor = "#ea580c";
                    } else if (incident.escalation_level === "elevated") {
                        borderColor = "#ca8a04";
                        badgeColor = "#ca8a04";
                    }

                    row.style.background = "#0f172a";
                    row.style.padding = "12px";
                    row.style.borderRadius = "10px";
                    row.style.border = `1px solid ${borderColor}`;

                    if (incident.escalation_level === "critical") {
                        row.style.boxShadow =
                            "0 0 18px rgba(220,38,38,0.45)";
                    }

                    row.innerHTML = `

                        ${incident.escalation_level === "critical" ? `
                        <div style="
                            background:#7f1d1d;
                            border:2px solid #dc2626;
                            color:white;
                            padding:10px;
                            border-radius:8px;
                            margin-bottom:10px;
                            font-weight:bold;
                        ">
                            🚨 CRITICAL INCIDENT - IMMEDIATE RESPONSE REQUIRED
                        </div>
                        ` : ""}
                    
                        <div style="
                            display:flex;
                            justify-content:space-between;
                            align-items:center;
                            gap:12px;
                            flex-wrap:wrap;
                        ">
                            <div>
                                <strong>Incident #${incident.id}</strong>
                                <div style="font-size:13px; opacity:0.8; margin-top:4px;">
                                    Source: ${incident.source}
                                </div>
                            </div>

                            <span style="
                                background:${badgeColor};
                                color:white;
                                padding:4px 10px;
                                border-radius:999px;
                                font-size:12px;
                                font-weight:bold;
                            ">
                                ${(incident.escalation_level || "normal").toUpperCase()}
                            </span>
                        </div>

                        <div style="margin-top:10px; font-size:14px;">
                            Status:
                            <strong>${(incident.status || "unknown").toUpperCase()}</strong>
                        </div>

                        <div style="margin-top:6px; font-size:13px; opacity:0.8;">
                            Created: ${formatRelativeTime(incident.created_at)}
                        </div>

                        <div style="margin-top:12px; display:flex; gap:10px; flex-wrap:wrap;">

                            ${
                                incident.status === "email_pending"
                                ? `
                                    <button onclick="acknowledgeIncident(${incident.id})" style="
                                        width:auto;
                                        background:#ca8a04;
                                        color:white;
                                        padding:8px 12px;
                                        border-radius:8px;
                                        border:none;
                                        font-weight:bold;
                                        cursor:pointer;
                                    ">
                                        Acknowledge
                                    </button>
                                `
                                : `
                                    <button disabled style="
                                        width:auto;
                                        background:#78716c;
                                        color:white;
                                        padding:8px 12px;
                                        border-radius:8px;
                                        border:none;
                                        font-weight:bold;
                                        opacity:0.7;
                                        cursor:not-allowed;
                                    ">
                                        Acknowledged
                                    </button>
                                `
                            }

                            ${
                                incident.status !== "resolved"
                                ? `
                                    <button onclick="resolveIncident(${incident.id})" style="
                                        width:auto;
                                        background:#22c55e;
                                        color:white;
                                        padding:8px 12px;
                                        border-radius:8px;
                                        border:none;
                                        font-weight:bold;
                                        cursor:pointer;
                                    ">
                                        Resolve
                                    </button>
                                `
                                : `
                                    <button disabled style="
                                        width:auto;
                                        background:#78716c;
                                        color:white;
                                        padding:8px 12px;
                                        border-radius:8px;
                                        border:none;
                                        font-weight:bold;
                                        opacity:0.7;
                                        cursor:not-allowed;
                                    ">
                                        Resolved
                                    </button>
                                `
                            }

                        </div>
                    `;

                    box.appendChild(row);
                });

            } catch(error) {
                console.error("Incident queue error:", error);

                const box = document.getElementById("incident-queue-box");
                if (box) {
                    box.innerHTML =
                        "<div style='color:#f87171;'>Could not load incident queue.</div>";
                }
            }
        }

        async function loadResolvedIncidentHistory() {
            const token = localStorage.getItem("token");

            try {
                const response = await fetch("/resolved-incidents", {
                    headers: {
                        "Authorization": "Bearer " + token
                    }
                });

                if (!response.ok) {
                    throw new Error("Resolved incidents failed");
                }

                const data = await response.json();
                const box = document.getElementById("resolved-incident-history-box");

                if (!box) return;

                box.innerHTML = "";

                const incidents = data.incidents || [];

                if (!incidents.length) {
                    box.innerHTML = "<div>No resolved incidents yet</div>";
                    return;
                }

                incidents.forEach(incident => {
                    const row = document.createElement("div");

                    row.style.background = "#064e3b";
                    row.style.padding = "12px";
                    row.style.borderRadius = "10px";
                    row.style.border = "1px solid #22c55e";

                    row.innerHTML = `
                        <strong>Incident #${incident.id}</strong>
                        <div style="font-size:13px; opacity:0.85; margin-top:6px;">
                            Source: ${incident.source}
                        </div>
                        <div style="font-size:13px; opacity:0.85; margin-top:6px;">
                            Severity: ${(incident.escalation_level || "normal").toUpperCase()}
                        </div>
                        <div style="font-size:13px; opacity:0.85; margin-top:6px;">
                            Resolved: ${formatRelativeTime(incident.resolved_at)}
                        </div>

                        <div style="
                            margin-top:10px;
                            padding:10px;
                            background:#022c22;
                            border-radius:8px;
                            border:1px solid #10b981;
                            font-size:13px;
                        ">
                            <strong>SOC Timeline:</strong><br>
                            Created: ${formatRelativeTime(incident.created_at)}<br>
                            Acknowledged: ${formatRelativeTime(incident.acknowledged_at)}<br>
                            Resolved: ${formatRelativeTime(incident.resolved_at)}
                        </div>
                    `;

                    box.appendChild(row);
                });

            } catch(error) {
                console.error("Resolved incident history error:", error);

                const box = document.getElementById("resolved-incident-history-box");
                if (box) {
                    box.innerHTML =
                        "<div style='color:#fecaca;'>Could not load resolved incident history.</div>";
                }
            }
        }

        async function acknowledgeIncident(id) {
            const token = localStorage.getItem("token");

            const response = await fetch(`/acknowledge-alert/${id}`, {
                method: "POST",
                headers: {
                    "Authorization": "Bearer " + token
                }
            });

            if (!response.ok) {
                alert("Could not acknowledge incident");
                return;
            }

            await loadIncidentSummary();
            await loadIncidentQueue();
            await loadResolvedIncidentHistory();
        }

        async function resolveIncident(id) {
            const token = localStorage.getItem("token");

            const response = await fetch(`/resolve-alert/${id}`, {
                method: "POST",
                headers: {
                    "Authorization": "Bearer " + token
                }
            });

            if (!response.ok) {
                alert("Could not resolve incident");
                return;
            }

            await loadIncidentSummary();
            await loadIncidentQueue();
            await loadResolvedIncidentHistory();
        }

        let dashboardRefreshing = false;

        async function refreshDashboardSafely() {
            if (dashboardRefreshing) {
                console.log("Dashboard refresh skipped: previous refresh still running");
                return;
            }

            dashboardRefreshing = true;

            try {
                await loadDashboard();
                await loadSourceAnalytics();
                await loadIngestionActivity();
                await loadIngestionErrors();
                await loadIncidentSummary();
                await loadIncidentQueue();
                await loadResolvedIncidentHistory();
            } catch (error) {
                console.error("Dashboard refresh error:", error);
            } finally {
                dashboardRefreshing = false;
            }
        }

        window.onload = function() {
            refreshDashboardSafely();
            loadBillingStatus();
            loadApiKey();

            setInterval(() => {
                refreshDashboardSafely();
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

                    const rawLog = (log.log || "").toLowerCase();
                    const attackType = (log.attack_type || "").toLowerCase();

                    const failed =
                        attackType.includes("failed") ||
                        rawLog.includes("failed login") ||
                        rawLog.includes("failed login attempts");

                    const sql =
                        attackType.includes("sql") ||
                        rawLog.includes("sql injection");

                    if (failed) failedCount++;
                    if (sql) sqlCount++;

                    let badgeText = log.severity || "LOW";
                    let badgeClass = "badge-low";

                    if (badgeText === "HIGH") {
                        badgeClass = "badge-high";
                    } else if (badgeText === "MEDIUM") {
                        badgeClass = "badge-medium";
                    }

                    if (["HIGH", "CRITICAL"].includes((log.severity || "LOW").toUpperCase())) {
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
            let socket;

            function connectWebSocket() {
                const protocol = window.location.protocol === "https:" ? "wss://" : "ws://";
                const wsUrl = protocol + window.location.host + "/ws/logs";

                socket = new WebSocket(wsUrl);

                socket.onopen = () => {
                    console.log("WebSocket connected");
                };

                socket.onmessage = (event) => {
                    const data = JSON.parse(event.data);
                    console.log("WS MESSAGE:", data);

                    if (data.type === "new_log") {
                        loadInitialLogs();
                    }
                };

                socket.onclose = () => {
                    console.log("WebSocket disconnected, reconnecting...");
                    setTimeout(connectWebSocket, 3000);
                };
            }
        
            window.onload = async () => {
                await loadInitialLogs();

                setInterval(() => {
                    loadInitialLogs();
                }, 3000);

                loadChart();
                loadAlerts();
                loadBlacklistCount();
                loadTopAttacker();

                // connectWebSocket();
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