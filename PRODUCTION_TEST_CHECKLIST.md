# Production Test Checklist

## 1. Authentication
- Register new user
- Login user
- Confirm dashboard loads
- Confirm logout works
- Confirm protected endpoints reject missing token

## 2. Billing / Usage
- Confirm free plan shows 20 daily logs
- Confirm usage counter increases
- Confirm free user hits limit
- Confirm Pro user gets higher limit
- Confirm upgrade/downgrade buttons work

## 3. API Key System
- Reveal API key
- Copy API key
- Regenerate API key
- Confirm old API key stops working
- Confirm new API key works

## 4. Log Analysis
- Submit normal log
- Submit failed-login log
- Submit SQL injection log
- Submit mixed failed-login + SQL log
- Confirm threat_score appears
- Confirm priority/severity appears

## 5. MITRE Mapping
- Brute force maps to T1110
- SQL injection maps to T1190
- Phishing maps to T1566
- Malware maps to T1204
- Unknown logs map to T0000

## 6. Webhook Ingestion
- Submit log through /webhook/log-api-key
- Confirm source appears
- Confirm received_at appears
- Confirm ingestion_method is api_key_webhook
- Confirm dashboard updates

## 7. Dashboard Stability
- Recent Saved Logs collapse/expand works
- Multiple View Details cards stay open
- Critical incidents show red banner
- Critical incidents sort to top
- Source analytics loads
- Source health loads
- Ingestion activity loads
- Ingestion errors load

## 8. Incident Workflow
- Critical incident appears in queue
- Acknowledge incident works
- Resolve incident works
- Resolved incident appears in history

## 9. Email Alerts
- Test email alert endpoint works
- Email alert event appears
- Cooldown prevents spam
- Incident queue updates

## 10. Launch Readiness
- Railway deploy succeeds
- Environment variables are set
- Stripe test mode works
- Database persists records
- No dashboard loading errors
- No console errors