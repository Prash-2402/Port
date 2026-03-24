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
| Production | Gunicorn + Gevent · Render |

---

## File Structure

```
port-scanner/
├── app.py              ← Flask routes, rate limiting, SSE streaming
├── scanner.py          ← Core scan logic (reusable module)
├── requirements.txt
├── Procfile
├── render.yaml         ← Render Blueprint config
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

## Deploy to Render

Render is a modern cloud host with a generous free tier. This project includes a `render.yaml` Blueprint for automated deployment.

1. **Push your code to GitHub**:
   ```bash
   cd port-scanner
   git branch -M main
   git remote add origin https://github.com/<your-username>/<your-repo>.git
   git push -u origin main
   ```

2. **Deploy via Blueprint**:
   - Create a free account at [render.com](https://render.com)
   - Go to your Dashboard → **New** → **Blueprint**
   - Connect your GitHub account and select this repository.
   
Render will automatically detect the app, install dependencies, start the Gunicorn server, and securely auto-generate your `SECRET_KEY` for you.

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
