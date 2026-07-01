import os
import select
import threading
import docker
from capture import SessionRecorder

docker_client = docker.from_env()

CONTAINER_IMAGE = "honeypot-mysh"
SECCOMP_PROFILE = os.path.abspath("seccomp-profile.json")


def _make_run_kwargs(container_name: str) -> dict:
    return dict(
        image=CONTAINER_IMAGE,
        name=container_name,
        network_mode="none",
        read_only=True,
        tmpfs={"/tmp": "size=10m,mode=1777"},
        cap_drop=["ALL"],
        security_opt=[
            "no-new-privileges",
            f"seccomp={SECCOMP_PROFILE}",
        ],
        mem_limit="64m",
        memswap_limit="64m",
        cpu_quota=25000,
        pids_limit=20,
        ulimits=[
            docker.types.Ulimit(name="nofile", soft=64, hard=64),
        ],
        stdin_open=True,
        tty=False,
        detach=True,
        remove=True,
        user="honeyuser",
    )


def handle_session(channel, src_ip, src_port,
                   auth_username=None, auth_password=None):
    recorder = SessionRecorder(
        src_ip=src_ip,
        src_port=src_port,
        auth_username=auth_username,
        auth_password=auth_password,
        env_snapshot={
            "TERM": os.environ.get("TERM", "xterm"),
            "honeypot_node": os.uname().nodename,
        },
    )
    session_id = recorder.start()
    container_name = f"honeypot-{session_id[:8]}"
    exit_reason = "normal_exit"
    container = None

    try:
        container = docker_client.containers.run(
            **_make_run_kwargs(container_name)
        )

        sock = container.attach_socket(params={
            "stdin": True,
            "stdout": True,
            "stderr": True,
            "stream": True,
        })
        sock._sock.setblocking(False)

        def pump_container_to_client():
            try:
                while True:
                    ready, _, _ = select.select([sock._sock], [], [], 1.0)
                    if not ready:
                        if _container_dead(container):
                            break
                        continue
                    chunk = sock._sock.recv(4096)
                    if not chunk:
                        break
                    recorder.record_output(chunk)
                    try:
                        channel.send(chunk)
                    except Exception:
                        break
            except Exception:
                pass

        output_thread = threading.Thread(
            target=pump_container_to_client, daemon=True
        )
        output_thread.start()

        while True:
            try:
                data = channel.recv(1024)
            except Exception:
                exit_reason = "error"
                break

            if not data:
                exit_reason = "client_disconnect"
                break

            recorder.record_input(data)

            try:
                sock._sock.sendall(data)
            except Exception:
                exit_reason = "killed"
                break

            if _container_dead(container):
                exit_reason = "killed"
                break

        output_thread.join(timeout=2)

    except docker.errors.ImageNotFound:
        channel.send(b"honeypot: image not found\r\n")
        exit_reason = "error"

    except docker.errors.APIError:
        channel.send(b"honeypot: container error\r\n")
        exit_reason = "error"

    finally:
        _kill_container(container)
        recorder.end(exit_reason=exit_reason, container_id=container_name)
        channel.close()

    return session_id


def _container_dead(container) -> bool:
    try:
        container.reload()
        return container.status not in ("running", "created")
    except docker.errors.NotFound:
        return True
    except Exception:
        return False


def _kill_container(container):
    if container is None:
        return
    try:
        container.kill()
    except Exception:
        pass
    try:
        container.remove(force=True)
    except Exception:
        pass