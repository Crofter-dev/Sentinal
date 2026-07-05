import json
import sqlite3
import struct
import time
import uuid
from pathlib import Path

from capture.credential_extractor import extract_credentials, extract_network_peers

DB_PATH      = Path(__file__).parent.parent / "db" / "honeypot.db"
SCHEMA_PATH  = Path(__file__).parent.parent / "db" / "schema.sql"
SESSIONS_DIR = Path(__file__).parent.parent / "sessions"

DIR_INPUT  = b"I"
DIR_OUTPUT = b"O"


def _ensure_db():
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())
    conn.commit()
    return conn


def record_auth_attempt(src_ip, src_port, username, password,
                        auth_type="password", success=False, session_id=None):
    conn = _ensure_db()
    conn.execute(
        (src_ip, src_port, time.time(), username, password,
         auth_type, int(success), session_id)
    )
    conn.commit()
    conn.close()


class SessionRecorder:
    def __init__(self, src_ip, src_port, auth_username=None,
                 auth_password=None, env_snapshot=None):
        self.session_id       = str(uuid.uuid4())
        self.src_ip           = src_ip
        self.src_port         = src_port
        self.auth_username    = auth_username
        self.auth_password    = auth_password
        self.env_snapshot     = env_snapshot or {}
        self.start_time       = None
        self.last_ks_ts       = None
        self.keystroke_seq    = 0
        self.output_seq       = 0
        self.command_seq      = 0
        self._line_buf        = bytearray()
        self._cap_file        = None
        self._conn            = None

    def start(self):
        self.start_time = time.time()
        self.last_ks_ts = self.start_time

        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        self._cap_file = open(SESSIONS_DIR / f"{self.session_id}.cap", "wb")
        self._conn = _ensure_db()

        self._conn.execute(
            (self.session_id, self.src_ip, self.src_port,
             self.auth_username, self.auth_password,
             self.start_time, json.dumps(self.env_snapshot)),
        )
        self._conn.commit()
        return self.session_id

    def end(self, exit_reason="normal_exit", container_id=None):
        end_time = time.time()
        if self._line_buf:
            self._flush_command_line()

        self._conn.execute(
            (end_time, end_time - self.start_time, exit_reason,
             container_id,
             str(SESSIONS_DIR / f"{self.session_id}.cap"),
             self.session_id),
        )
        self._conn.commit()
        self._conn.close()
        self._cap_file.close()

    def _ts(self):
        return (time.time() - self.start_time) * 1000.0

    def _write_cap(self, direction, ts_ms, data):
        self._cap_file.write(direction)
        self._cap_file.write(struct.pack(">d", ts_ms))
        self._cap_file.write(struct.pack(">I", len(data)))
        self._cap_file.write(data)
        self._cap_file.flush()

    def record_input(self, data: bytes):
        now       = time.time()
        ts_ms     = (now - self.start_time) * 1000.0
        delta_ms  = (now - self.last_ks_ts) * 1000.0
        self.last_ks_ts = now

        self._write_cap(DIR_INPUT, ts_ms, data)

        self.keystroke_seq += 1
        self._conn.execute(
            (self.session_id, self.keystroke_seq, ts_ms, delta_ms, data.hex()),
        )
        self._conn.commit()
        self._process_input(data, ts_ms)

    def record_output(self, data: bytes):
        ts_ms = self._ts()
        self._write_cap(DIR_OUTPUT, ts_ms, data)

        self.output_seq += 1
        self._conn.execute(
            (self.session_id, self.output_seq, ts_ms, data)
        )
        self._conn.commit()

    def _process_input(self, data: bytes, ts_ms: float):
        for byte in data:
            if byte in (0x7F, 0x08):
                if self._line_buf:
                    self._line_buf.pop()
            elif byte in (0x0D, 0x0A):
                self._flush_command_line(ts_ms)
            elif byte == 0x03:
                self._line_buf.clear()
            elif 0x20 <= byte < 0x7F:
                self._line_buf.append(byte)

    def _flush_command_line(self, ts_ms=None):
        if not self._line_buf:
            return
        line   = self._line_buf.decode("utf-8", errors="replace")
        ts_ms  = ts_ms if ts_ms is not None else self._ts()
        self._line_buf.clear()

        self.command_seq += 1
        self._conn.execute(
            (self.session_id, self.command_seq, ts_ms, line)
        )
        self._conn.commit()

        self._run_extractors(line, ts_ms)

    def _run_extractors(self, line: str, ts_ms: float):
        for cred in extract_credentials(line, ts_ms):
            self._conn.execute(
                (self.session_id, cred["ts_offset_ms"], cred["source"],
                 cred["credential_type"], cred["key"],
                 cred["value"], cred["raw_context"]),
            )

        for peer in extract_network_peers(line, ts_ms):
            self._conn.execute(
                """INSERT INTO network_peers
                   (session_id, ts_offset_ms, direction, host, port,
                    protocol, raw_context)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (self.session_id, peer["ts_offset_ms"], peer["direction"],
                 peer["host"], peer["port"],
                 peer["protocol"], peer["raw_context"]),
            )

        self._conn.commit()

def replay_capture(session_id, speed=1.0):
    cap_path = SESSIONS_DIR / f"{session_id}.cap"
    last_ts  = 0.0
    with open(cap_path, "rb") as f:
        while True:
            header = f.read(1)
            if not header:
                break
            direction  = header
            ts_ms      = struct.unpack(">d", f.read(8))[0]
            length     = struct.unpack(">I", f.read(4))[0]
            data       = f.read(length)
            wait       = (ts_ms - last_ts) / 1000.0 / speed
            if wait > 0:
                time.sleep(wait)
            last_ts = ts_ms
            yield (direction.decode(), data)
