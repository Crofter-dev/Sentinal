# Honeypot

SSH honeypot with a disposable `mysh` container backend, full forensic session capture, credential extraction, and a Flask dashboard.

## Project structure

```
honeypot/
├── server.py                    # SSH server — run this
├── integration_example.py       # docker-py container spawner
├── seccomp-profile.json         # container syscall allowlist
├── requirements.txt
├── capture/
│   ├── __init__.py
│   ├── capture.py               # SessionRecorder, record_auth_attempt
│   └── credential_extractor.py  # regex patterns for credentials and IPs
├── dashboard/
│   ├── dashboard.py             # Flask app
│   └── templates/
│       ├── base.html
│       ├── session_list.html
│       └── session_detail.html
└── db/
    └── schema.sql               # SQLite schema
```

Runtime directories (created automatically):

```
honeypot/
├── db/honeypot.db               # created on first run
├── sessions/                    # .cap replay files, one per session
└── host_key                     # RSA host key, generated on first run
```

---

## Requirements

- Python 3.11+
- Docker Engine running and accessible at `/var/run/docker.sock`
- The `honeypot-mysh` Docker image built from `shell.c`
- Port 2222 open (or 22 with root — see below)

---

## Setup

### 1. Install Python dependencies

```bash
cd honeypot/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Build the mysh container image

```bash
# From the directory containing shell.c and the Dockerfile
docker build -t honeypot-mysh .
```

Confirm it exists:

```bash
docker images | grep honeypot-mysh
```

### 3. Initialise the database

The schema is applied automatically on first run of `server.py`. If you want to apply it manually:

```bash
sqlite3 db/honeypot.db < db/schema.sql
```

### 4. (Optional) Copy the seccomp profile to the right path

`integration_example.py` resolves `seccomp-profile.json` relative to its own directory. If you run the server from a different working directory, set the absolute path:

```bash
export SECCOMP_PROFILE=/absolute/path/to/honeypot/seccomp-profile.json
```

Or edit `SECCOMP_PROFILE` at the top of `integration_example.py` directly.

---

## Running

### Start the SSH honeypot server

```bash
# Default: port 2222 (no root needed)
python3 server.py

# To listen on port 22 (requires root or CAP_NET_BIND_SERVICE)
sudo python3 server.py
# — or —
sudo setcap 'cap_net_bind_service=+ep' $(which python3)
python3 server.py
```

You should see:

```
[*] Listening on 0.0.0.0:2222
```

### Test the connection

From another terminal or machine:

```bash
ssh root@<your-host> -p 2222
```

The server will accept after a realistic number of failed attempts. Try a few wrong passwords first — all are logged.

### Start the dashboard

```bash
cd dashboard/
python3 dashboard.py
```

Open `http://127.0.0.1:5000` in a browser. Sessions appear as they complete.

---

## Deployment notes

### Running as a service (systemd)

Create `/etc/systemd/system/honeypot.service`:

```ini
[Unit]
Description=SSH Honeypot
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/honeypot
ExecStart=/opt/honeypot/venv/bin/python3 server.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now honeypot
sudo systemctl status honeypot
```

### Firewall

Only expose port 2222 (or 22). The dashboard runs on 127.0.0.1 and should never be exposed directly — put it behind nginx + auth if you need remote access.

```bash
# UFW example
sudo ufw allow 2222/tcp
sudo ufw deny 5000
```

### Log rotation for .cap files

Sessions directory grows unbounded. Add a cron job or logrotate rule:

```bash
# Delete .cap files older than 30 days
0 3 * * * find /opt/honeypot/sessions -name "*.cap" -mtime +30 -delete
```

---

## How it works

```
Attacker SSH client
        │  TCP port 2222
        ▼
server.py
  · Paramiko SSH transport
  · Fake OpenSSH banner
  · Accepts after N failed attempts
  · Logs every attempt via record_auth_attempt()
        │  handle_session()
        ▼
integration_example.py
  · Spawns disposable Docker container (honeypot-mysh)
  · Isolation: --network=none, --read-only, --cap-drop=ALL,
               --memory=64m, --pids-limit=20, seccomp profile
  · Bridges attacker ↔ container via attach_socket()
  · Every byte flows through SessionRecorder
        │
        ├── capture.py
        │     · Keystroke timing (delta_ms per key)
        │     · Command line reconstruction (handles backspace/Ctrl+C)
        │     · Binary .cap replay file
        │     · SQLite: sessions, keystrokes, commands, output_chunks
        │
        └── credential_extractor.py
              · Regex patterns: curl, mysql, ssh, aws, wget,
                sshpass, bearer tokens, env vars, URLs
              · IP/port/hostname extraction
              · SQLite: credentials, network_peers
```

---

## Querying the database

```bash
sqlite3 db/honeypot.db
```

Useful queries:

```sql
-- All auth attempts from a specific IP
SELECT username, password, success, datetime(ts, 'unixepoch')
FROM auth_attempts
WHERE src_ip = '1.2.3.4'
ORDER BY ts;

-- Sessions with the most commands
SELECT session_id, src_ip, auth_username,
       COUNT(*) AS cmd_count, duration_sec
FROM sessions
JOIN commands USING (session_id)
GROUP BY session_id
ORDER BY cmd_count DESC
LIMIT 20;

-- All credentials extracted
SELECT s.src_ip, c.credential_type, c.key, c.value
FROM credentials c
JOIN sessions s USING (session_id)
ORDER BY c.id;

-- Scripted vs human sessions (low delta_ms variance = scripted)
SELECT session_id,
       AVG(delta_ms) AS avg_ms,
       AVG(delta_ms * delta_ms) - AVG(delta_ms) * AVG(delta_ms) AS variance
FROM keystrokes
GROUP BY session_id
ORDER BY variance ASC;

-- Outbound connection attempts
SELECT s.src_ip, n.host, n.port, n.protocol
FROM network_peers n
JOIN sessions s USING (session_id)
ORDER BY n.id;
```

---

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SECCOMP_PROFILE` | `seccomp-profile.json` (relative) | Absolute path to seccomp profile |
| `HONEYPOT_PORT` | `2222` | SSH listen port |
| `HONEYPOT_HOST` | `0.0.0.0` | SSH listen address |
| `DASHBOARD_PORT` | `5000` | Flask dashboard port |

---

## Security notes

- The honeypot runs real commands via `execvp` inside the container. Isolation is provided by Docker + seccomp + capability drops, not emulation. Do not run this without Docker isolation.
- Never expose port 5000 (dashboard) to the internet. It has no authentication.
- The `host_key` file contains a private RSA key. Do not commit it to version control.
- Captured credentials are stored in plaintext in SQLite. Secure the `db/` directory appropriately (`chmod 700 db/`).
