import re
import urllib.parse

_ARG_PATTERNS = [
    ("http_basic", "curl_user",
     re.compile(r'curl\b.*?(?:-u|--user)\s+([^\s:]+):([^\s]+)', re.I)),

    ("http_basic", "wget_user",
     re.compile(r'wget\b.*?--user[=\s]+([^\s]+)', re.I)),
    ("http_basic", "wget_password",
     re.compile(r'wget\b.*?--password[=\s]+([^\s]+)', re.I)),

    ("db_credential", "mysql_user",
     re.compile(r'mysql\b.*?(?:-u\s*|--user[=\s]+)([^\s\-]+)', re.I)),
    ("db_credential", "mysql_password",
     re.compile(r'mysql\b.*?(?:-p\s*|--password[=\s]+)([^\s\-]+)', re.I)),

    ("db_credential", "psql_user",
     re.compile(r'psql\b.*?(?:-U\s*|--username[=\s]+)([^\s\-]+)', re.I)),
    ("db_credential", "pg_uri",
     re.compile(r'postgresql://([^@\s]+)@', re.I)),

    ("db_credential", "redis_auth",
     re.compile(r'redis-cli\b.*?(?:-a\s+|--pass\s+)([^\s]+)', re.I)),

    ("ssh_target", "ssh_user_host",
     re.compile(r'\bssh\b.*?([a-zA-Z0-9_\-]+)@([\w.\-]+)', re.I)),
    ("ssh_target", "ssh_l_user",
     re.compile(r'\bssh\b.*?-l\s+([^\s]+)', re.I)),

    ("ssh_credential", "sshpass",
     re.compile(r'sshpass\b.*?-p\s+([^\s]+)', re.I)),

    ("ftp_target", "ftp_user_host",
     re.compile(r'\bftp\b.*?([a-zA-Z0-9_\-]+)@([\w.\-]+)', re.I)),

    ("cloud_credential", "aws_key_id",
     re.compile(r'AWS_ACCESS_KEY_ID[=\s]+([A-Z0-9]{16,})', re.I)),
    ("cloud_credential", "aws_secret",
     re.compile(r'AWS_SECRET_ACCESS_KEY[=\s]+([^\s]+)', re.I)),

    ("generic_credential", "generic_password",
     re.compile(r'(?:--password|--passwd|--secret|--token|--api-key)[=\s]+([^\s]+)', re.I)),

    ("http_token", "bearer_token",
     re.compile(r'Authorization:\s*Bearer\s+([^\s"\']+)', re.I)),

    ("http_basic", "url_userinfo",
     re.compile(r'https?://([^@\s]+):([^@\s]+)@', re.I)),
]

_ENV_PATTERNS = [
    re.compile(r'export\s+([A-Z_][A-Z0-9_]*)=["\']?([^\s"\']+)["\']?', re.I),
]

_SENSITIVE_ENV_KEYS = {
    "password", "passwd", "secret", "token", "key", "api_key",
    "access_key", "secret_key", "auth", "credential", "private_key",
    "aws_access_key_id", "aws_secret_access_key", "aws_session_token",
    "github_token", "gitlab_token", "database_url", "db_password",
    "redis_password", "mongo_password", "mysql_password", "pg_password",
}

_IP_PORT_PATTERNS = [
    re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b'),
    re.compile(r'-H\s+([a-zA-Z0-9.\-]+)\s+-P\s+(\d+)', re.I),
    re.compile(r'--host[=\s]+([^\s]+).*?--port[=\s]+(\d+)', re.I),
    re.compile(r'(?:nc|ncat|netcat)\s+([^\s]+)\s+(\d+)', re.I),
    re.compile(r'(?:connect|open)\s+([^\s]+)\s+(\d+)', re.I),
]

_HOSTNAME_PATTERN = re.compile(
    r'\b(?:ssh|ftp|curl|wget|nc|ncat|rsync|scp)\b.*?@?([\w][\w.\-]{2,}\.[a-z]{2,})\b', re.I
)

_PROTOCOL_MAP = {
    "curl": "http", "wget": "http",
    "ssh": "ssh", "scp": "ssh", "sftp": "ssh", "sshpass": "ssh",
    "ftp": "ftp", "nc": "tcp", "ncat": "tcp", "netcat": "tcp",
    "mysql": "mysql", "psql": "postgresql", "redis-cli": "redis",
    "mongo": "mongodb",
}


def extract_credentials(command_line: str, ts_offset_ms: float) -> list[dict]:
    results = []
    cmd = command_line.strip()

    for cred_type, key_name, pattern in _ARG_PATTERNS:
        m = pattern.search(cmd)
        if m:
            groups = m.groups()
            if len(groups) >= 2:
                value = f"{groups[0]}:{groups[1]}"
                key = key_name
            else:
                value = groups[0]
                key = key_name
            results.append({
                "ts_offset_ms": ts_offset_ms,
                "source": "command_argument",
                "credential_type": cred_type,
                "key": key,
                "value": value,
                "raw_context": cmd[:200],
            })

    for pattern in _ENV_PATTERNS:
        for m in pattern.finditer(cmd):
            env_key = m.group(1)
            env_val = m.group(2)
            if any(s in env_key.lower() for s in _SENSITIVE_ENV_KEYS):
                results.append({
                    "ts_offset_ms": ts_offset_ms,
                    "source": "environment_variable",
                    "credential_type": "env_credential",
                    "key": env_key,
                    "value": env_val,
                    "raw_context": cmd[:200],
                })

    return results


def extract_network_peers(command_line: str, ts_offset_ms: float) -> list[dict]:
    results = []
    cmd = command_line.strip()

    first_token = cmd.split()[0] if cmd.split() else ""
    protocol = _PROTOCOL_MAP.get(first_token.lower(), "unknown")

    for pattern in _IP_PORT_PATTERNS:
        for m in pattern.finditer(cmd):
            host, port = m.group(1), m.group(2)
            if _is_private_ip(host):
                continue
            results.append({
                "ts_offset_ms": ts_offset_ms,
                "direction": "outbound",
                "host": host,
                "port": int(port),
                "protocol": protocol,
                "raw_context": cmd[:200],
            })

    for m in _HOSTNAME_PATTERN.finditer(cmd):
        host = m.group(1)
        results.append({
            "ts_offset_ms": ts_offset_ms,
            "direction": "outbound",
            "host": host,
            "port": None,
            "protocol": protocol,
            "raw_context": cmd[:200],
        })

    return results


def _is_private_ip(ip: str) -> bool:
    try:
        parts = list(map(int, ip.split(".")))
        if len(parts) != 4:
            return False
        return (
            parts[0] == 10
            or (parts[0] == 172 and 16 <= parts[1] <= 31)
            or (parts[0] == 192 and parts[1] == 168)
            or parts[0] == 127
        )
    except Exception:
        return False
