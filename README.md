# 🛡️ OWASP Top 10 Security Scanner — v2.0

> ⚠️ Educational and **authorized testing only**. Never scan without written permission.

## 🆕 v2.0 Upgrades

| # | Feature | Interview line |
|---|---|---|
| 1 | Multi-threaded Crawler | "I built a concurrent crawler using ThreadPoolExecutor to auto-discover and test internal pages" |
| 2 | Multithreaded Scanning | "7 checks run in parallel — 6 workers cut scan time significantly" |
| 3 | Advanced Detection | "4-signal detection: error patterns, response-length delta, status deviation, time spike" |
| 4 | Dashboard UI | "Full real-time dashboard with live terminal log, KPI strip, donut chart, crawl map" |
| 5 | PDF + JSON Export | "Generates reports in JSON and PDF via ReportLab for stakeholder review" |
| 6 | Docker + Compose | "Multi-stage Dockerfile, non-root user, health check, Gunicorn" |

## 📁 Files
```
app.py               Flask routes (/, /scan, /export/json, /export/pdf, /health)
scanner.py           7 checks + Crawler + advanced detection (multithreaded)
report.py            Report builder + ReportLab PDF + plain-text fallback
requirements.txt
Dockerfile           Multi-stage, non-root, Gunicorn
docker-compose.yml   One-command local run
templates/index.html Full dashboard UI
```

## 🚀 Run Locally
```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app.py        # → http://localhost:5000
```

## 🐳 Docker (Upgrade 6)
```bash
# One-command start
docker compose up --build

# Manual
docker build -t owasp-scanner:v2 .
docker run -d --name owasp-scanner -p 5000:5000 --restart unless-stopped owasp-scanner:v2
docker logs -f owasp-scanner
docker stop owasp-scanner && docker rm owasp-scanner
```

## 📡 API
| Method | Endpoint | Purpose |
|---|---|---|
| GET  | /health       | Health check (Docker/k8s) |
| POST | /scan         | Run scan → JSON report |
| POST | /export/json  | Downloadable JSON |
| POST | /export/pdf   | Downloadable PDF |

## 🧪 Safe Test Targets
- http://testphp.vulnweb.com  (Acunetix demo)
- DVWA: docker run -p 80:80 vulnerables/web-dvwa
- TryHackMe / HackTheBox lab VMs only
