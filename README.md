# LogSense AI

Live, AI-powered log analysis. Connect your cloud logs, watch incidents appear the moment they start, and ask questions in plain English.
Internship project at **Beehive Systems Pvt. Ltd.**

## What it does
- **Accounts:** sign up / log in, or use the instant **demo** (sample data + live demo stream, no sign-up). Every account has its own private database.
- **Live sources:** AWS CloudWatch, AWS S3, Google Cloud Logging, a web link, or the built-in demo stream. The server checks every few seconds, reads only NEW events, and the dashboard updates instantly (Server-Sent Events). Each user supplies their own read-only cloud keys, stored encrypted.
- **Pipeline:** parse mixed formats -> mask emails/IPs/tokens -> group similar lines into patterns -> store -> detect incidents -> alert on new error patterns.
- **Ask anything:** the AI writes a read-only SQL query for your question, the app runs it in a sandbox, and the AI explains the real result in plain text. Without an AI key, a rule-based fallback answers.
- **Accurate answers:** counts, latest/first log, per-service breakdowns and log-number lookups are computed exactly from the database (no AI, no AI quota used). Everything else goes to the AI, which receives exact totals for the whole dataset plus real matching log lines; its answer is checked (no blank values, every number must exist in the data, invented log numbers rejected), retried once, and replaced by the exact query result if it still cannot be trusted.
- **Safety:** passwords hashed (PBKDF2), signed HttpOnly session cookie, CSRF header, login throttling, per-account daily AI limits, upload size and storage caps, SQL sandbox (SELECT only, two tables, read-only), SSRF protection for links, security headers, one-click account deletion.

## Run on your computer (Windows)
Double-click `run.bat`, or:
```
python -m venv venv
venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
copy .env.example .env
python -m uvicorn logsense.app:app --reload
```
Open http://localhost:8000 and click **Try the live demo**. Tests: `python -m pip install -r requirements-dev.txt` then `python -m pytest -q`.

## Deploy (public URL)
You need: this folder in a GitHub repo, an AI key (e.g. Groq), and a host that runs Docker **with a persistent disk** (accounts and data live in `/data`; without a disk they are lost on every redeploy).

1. Generate a secret: `python -c "import secrets;print(secrets.token_hex(32))"`
2. **Render:** New > Blueprint > select the repo (`render.yaml` is included). Add `OPENAI_API_KEY` (and optionally `LOGSENSE_AUTHOR`). Render generates `LOGSENSE_SECRET`. Check Render's current plans for disk support.
3. **Railway / Fly.io / any Docker host:** build the `Dockerfile`, mount a volume at `/data`, and set the environment variables below. Run exactly **one** instance/worker (it also runs the live poller).
4. **Your own server:** copy `.env.example` to `.env`, fill it in, then `docker compose up -d --build`. Put a reverse proxy with HTTPS (Caddy / nginx) in front.
5. Open the URL, click **Try the live demo**, then create an account and test a live source.

| Environment variable | Required | Meaning |
|---|---|---|
| `LOGSENSE_SECRET` | yes | Signs logins and encrypts cloud keys. Keep it stable: changing it logs everyone out and makes saved cloud keys unreadable. |
| `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `LOGSENSE_MODEL`, `LOGSENSE_PROVIDER` | for AI | Any OpenAI-compatible provider (Groq shown in `.env.example`), or Gemini / Claude / Ollama. |
| `LOGSENSE_HOSTED=1` | set by Dockerfile | Disables API docs, adds HSTS, and never uses the server's own cloud access. |
| `LOGSENSE_GUEST_AI_LIMIT`, `LOGSENSE_USER_AI_LIMIT` | no | AI questions per day (10 / 50). |
| `LOGSENSE_MAX_UPLOAD_MB`, `LOGSENSE_MAX_LOGS` | no | Upload size (10) and stored lines per account (100000). |
| `LOGSENSE_AUTHOR` | no | Name shown in the landing page footer. |

## Architecture
```
Browser (landing + dashboard) <-- SSE --> FastAPI --+-- auth.db (users, usage)
                                                    +-- users/<id>.db (one SQLite per user: logs, patterns, sources)
Live poller thread --> every user's sources --> parse > mask > group > store --> pushes updates
AI provider (Groq / Gemini / Claude / Ollama) <-- question planning + answer, daily-limited per account
```

## Known limits
- "Live" is polling (minimum every 3 seconds), not a push from the cloud.
- SQLite per user suits a demo or small team on one instance. For scale: PostgreSQL/OpenSearch, a queue (Kafka) and several workers.
- Cloud connectors are tested with simulated clients, not against a live AWS/Google account.
- The AI can misread an unusual question; "How I found this" shows the exact query it ran.
- Email verification and password reset are not implemented.
