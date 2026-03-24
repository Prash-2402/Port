# ⚡ Port Scanner + Vulnerability Reporter

A fast, production-ready TCP port scanner with a live hacker-themed web UI. Scans open ports in real time using 200 threads, maps them to service names, and flags high-risk ports with known CVE references. Built for deployment on Render (free tier).

> **Legal Notice**: This tool is for educational and authorized testing only. Only scan hosts you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3 · Flask · flask-limiter |
| Scanning | `socket` · `concurrent.futures.ThreadPoolExecutor` |
| Streaming | Server-Sent Events (SSE) |
| Frontend | Single HTML file · Vanilla JS · CSS |
| Production | Gunicorn + Gthread · Render |

---

## File Structure

```
port-scanner/
├── app.py              ← Flask routes, rate limiting, SSE streaming
├── scanner.py          ← Core scan logic (reusable module)
├── requirements.txt
├── Procfile
├── .gitignore
└── templates/
    └── index.html      ← Full frontend (disclaimer modal + live UI)
```

---

## Run Locally

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set a secret key (optional for local dev)
set SECRET_KEY=any-random-string   # Windows
export SECRET_KEY=any-random-string  # Mac/Linux

# 3. Start the server
python app.py
```

Open **http://localhost:5000** in your browser.

---

## Deploy to Render (Free Tier)

Render offers a generous free tier. You can deploy this manually as a Web Service to avoid Blueprint payment requirements.

1. **Create the Web Service**:
   - Go to your Dashboard at **[dashboard.render.com](https://dashboard.render.com)**.
   - Click **New** → **Web Service**.
   - Select **Build and deploy from a Git repository** and connect this repository.

2. **Configure the Service**:
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --worker-class gthread --threads 4 --timeout 60`

3. **Set Environment Variables**:
   Under the *Environment Variables* section, add these variables:
   - `SECRET_KEY`: (Click the *Generate* button or type a random string)
   - `PYTHON_VERSION`: `3.11.0`

Click **Create Web Service** and your app will be live securely in a few minutes!

---

## Security Features

| Feature | Implementation |
|---------|---------------|
| Rate limiting | 1 scan per IP per 60 seconds (flask-limiter) |
| Disclaimer gate | Server-enforced via signed Flask session cookie |
| Private IP blocking | Rejects 127.x, 10.x, 172.16–31.x, 192.168.x via `ipaddress` module |
| Input sanitization | Regex validation — only `[A-Za-z0-9.\-]` allowed in target |
| Scan timeout | 30-second hard limit per scan |
| Port range cap | Maximum 1000 ports per scan |
| No stack traces | All errors return `{error: "message"}` — no internals exposed |
| Debug mode | OFF in production (`debug=False`) |

---

## API Reference

| Method | Route | Description |
|--------|-------|-------------|
| `GET` | `/` | Serve web UI |
| `POST` | `/agree` | Accept legal disclaimer (sets session cookie) |
| `POST` | `/scan` | Validate & start scan, returns `{scan_id, ip, ...}` |
| `GET` | `/stream/<scan_id>` | SSE stream: `{percent}`, `{done, results}`, `{error}` |

---

## Screenshot

![App UI](screenshot.png)

> Replace `screenshot.png` with an actual screenshot after first deployment.
