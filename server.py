import os
import socket
import sys
import threading
import time
import paramiko

sys.path.insert(0, os.path.dirname(__file__))

from capture.capture import record_auth_attempt
from integration_example import handle_session

HOST_KEY_PATH = os.path.join(os.path.dirname(__file__), "host_key")
LISTEN_HOST   = "0.0.0.0"
LISTEN_PORT   = 2222
BANNER        = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
MAX_ATTEMPTS  = 8
AUTH_DELAY    = 1.5


def _load_or_create_host_key():
    if os.path.exists(HOST_KEY_PATH):
        return paramiko.RSAKey.from_private_key_file(HOST_KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
    return key


class HoneypotAuthHandler(paramiko.ServerInterface):

    def __init__(self, src_ip, src_port):
        self.src_ip       = src_ip
        self.src_port     = src_port
        self.username     = None
        self.password     = None
        self.attempts     = 0
        self.auth_event   = threading.Event()
        self.pty_width    = 80
        self.pty_height   = 24

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.attempts += 1
        time.sleep(AUTH_DELAY)

        success = self.attempts >= MAX_ATTEMPTS

        record_auth_attempt(
            src_ip=self.src_ip,
            src_port=self.src_port,
            username=username,
            password=password,
            auth_type="password",
            success=success,
        )

        if success:
            self.username = username
            self.password = password
            self.auth_event.set()
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height,
                                   pixelwidth, pixelheight, modes):
        self.pty_width  = width
        self.pty_height = height
        return True

    def check_channel_shell_request(self, channel):
        self.auth_event.set()
        return True

    def check_channel_window_change_request(self, channel, width, height,
                                             pixelwidth, pixelheight):
        self.pty_width  = width
        self.pty_height = height
        return True


def _handle_connection(client_sock, src_ip, src_port, host_key):
    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = BANNER
        transport.add_server_key(host_key)

        auth_handler = HoneypotAuthHandler(src_ip, src_port)
        transport.start_server(server=auth_handler)

        channel = transport.accept(timeout=30)
        if channel is None:
            return

        auth_handler.auth_event.wait(timeout=30)

        handle_session(
            channel=channel,
            src_ip=src_ip,
            src_port=src_port,
            auth_username=auth_handler.username,
            auth_password=auth_handler.password,
        )

    except Exception:
        pass
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_sock.close()
        except Exception:
            pass


def run():
    host_key   = _load_or_create_host_key()
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((LISTEN_HOST, LISTEN_PORT))
    server_sock.listen(100)

    print(f"[*] Listening on {LISTEN_HOST}:{LISTEN_PORT}")

    while True:
        try:
            client_sock, (src_ip, src_port) = server_sock.accept()
            print(f"[+] Connection from {src_ip}:{src_port}")

            t = threading.Thread(
                target=_handle_connection,
                args=(client_sock, src_ip, src_port, host_key),
                daemon=True,
            )
            t.start()

        except KeyboardInterrupt:
            print("\n[*] Shutting down")
            break
        except Exception as e:
            print(f"[!] Accept error: {e}")

    server_sock.close()


if __name__ == "__main__":
    run()
