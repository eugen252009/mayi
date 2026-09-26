import json
import os
import pty
import select
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest


BROKER = "a" * 48
CHALLENGE = "b" * 48
DIGEST = "c" * 64
VIEW = "d" * 48
BINARY = Path(os.environ.get("MAYI_EXECUTOR_BIN", "executor/target/debug/mayi-executor"))


def _read_exact(conn, size):
    data = bytearray()
    while len(data) < size:
        part = conn.recv(size - len(data))
        if not part:
            raise EOFError("short frame")
        data.extend(part)
    return bytes(data)


def _fake_authority(path, count):
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen()
    listener.settimeout(10)
    messages = []
    errors = []

    def serve():
        try:
            for _ in range(count):
                conn, _ = listener.accept()
                with conn:
                    size = int.from_bytes(_read_exact(conn, 4), "big")
                    msg = json.loads(_read_exact(conn, size))
                    messages.append(msg)
                    ty = msg["type"]
                    if ty == "LIST_PENDING":
                        response = {
                            "ok": True,
                            "protocol": 5,
                            "response_to": ty,
                            "broker_instance_id": BROKER,
                            "pending": [{
                                "challenge_id": CHALLENGE,
                                "request_digest": DIGEST,
                                "requester_uid": os.getuid(),
                                "expires_at": int(time.time()) + 200,
                            }],
                        }
                    elif ty == "GET_CHALLENGE":
                        response = {
                            "ok": True,
                            "protocol": 5,
                            "response_to": ty,
                            "type": "CHALLENGE_VIEW",
                            "status": "DISPLAYED",
                            "state": "PENDING_APPROVAL",
                            "broker_instance_id": BROKER,
                            "challenge_id": CHALLENGE,
                            "request_digest": DIGEST,
                            "view_id": VIEW,
                            "view_expires_at": int(time.time()) + 50,
                            "rendered": "TEST APPROVAL VIEW",
                        }
                    else:
                        status = {
                            "APPROVE_CHALLENGE": "APPROVED",
                            "DENY_CHALLENGE": "DENIED",
                            "EXPLAIN_CHALLENGE": "EXPLAINED",
                        }[ty]
                        response = {
                            "ok": True,
                            "protocol": 5,
                            "response_to": ty,
                            "status": status,
                            "authorized": ty == "APPROVE_CHALLENGE",
                            "broker_instance_id": BROKER,
                            "challenge_id": CHALLENGE,
                            "request_digest": DIGEST,
                            "view_id": VIEW,
                        }
                    payload = json.dumps(response, separators=(",", ":")).encode()
                    conn.sendall(len(payload).to_bytes(4, "big") + payload)
        except Exception as exc:  # surfaced in the test thread
            errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return messages, errors, thread


def _console(binary, socket_path, master, slave, selection, decision, require_decision=True):
    proc = subprocess.Popen(
        [str(binary), "--approval-console", "--approval-socket", str(socket_path), "--broker-uid", str(os.getuid())],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
    )
    output = bytearray()
    selected = False
    decided = False
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.05)
        if ready:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                chunk = b""
            if chunk:
                output.extend(chunk)
                if b"Select request number" in output and not selected:
                    os.write(master, selection)
                    selected = True
                if b"Decision [approve/deny/explain" in output and not decided:
                    if decision is not None:
                        os.write(master, decision)
                    decided = True
        if proc.poll() is not None:
            break
    if proc.poll() is None:
        proc.kill()
        proc.wait()
        raise AssertionError("approval console did not terminate")
    assert selected and (decided or not require_decision)
    return proc.returncode, bytes(output), selected, decided


@pytest.mark.parametrize("input_bytes, expected", [
    (b"approve\n", "APPROVE_CHALLENGE"),
    (b"deny\n", "DENY_CHALLENGE"),
    (b"explain\n", "EXPLAIN_CHALLENGE"),
    (b"approve\nextra\n", None),
    (b"approve\n\n", None),
    (b"approve\r\n", None),
    (b"approve extra\n", None),
    (b" approve\n", None),
    (b"approve \n", None),
    (b"approve\t\n", None),
    (b"approve\rjunk\n", None),
    ("apprové\n".encode(), None),
    ("аpprove\n".encode(), None),
    (b"\n", None),
])
def test_console_decision_frame_is_exact_and_live(input_bytes, expected, tmp_path):
    binary = BINARY
    if not binary.exists():
        pytest.skip("build mayi-executor first")
    path = tmp_path / "approval.sock"
    messages, errors, server = _fake_authority(path, 2 if expected is None else 3)
    master, slave = pty.openpty()
    try:
        rc, output, selected, decided = _console(binary, path, master, slave, b"0\n", input_bytes)
        if expected is None:
            assert rc != 0
            assert [m["type"] for m in messages] == ["LIST_PENDING", "GET_CHALLENGE"]
        else:
            assert rc == 0
            assert messages[-1]["type"] == expected
            display = {"APPROVE_CHALLENGE": "APPROVED", "DENY_CHALLENGE": "DENIED", "EXPLAIN_CHALLENGE": "EXPLAINED"}[expected]
            assert display in output.decode("utf-8", "replace")
        server.join(timeout=10)
        assert not server.is_alive()
        assert not errors
    finally:
        os.close(master)
        os.close(slave)


def test_rejected_multiline_input_does_not_leak_to_next_console(tmp_path):
    if not BINARY.exists():
        pytest.skip("build mayi-executor first")
    path = tmp_path / "approval.sock"
    messages, errors, server = _fake_authority(path, 5)
    master, slave = pty.openpty()
    try:
        rc, _, selected, decided = _console(BINARY, path, master, slave, b"0\n", b"approve\nextra\n")
        assert rc != 0 and selected and decided
        assert [m["type"] for m in messages] == ["LIST_PENDING", "GET_CHALLENGE"]
        # The first invocation flushed its input queue and exited. A new invocation
        # needs a fresh selection and cannot consume the old trailing bytes.
        rc, output, selected, decided = _console(BINARY, path, master, slave, b"0\n", b"approve\n")
        assert rc == 0 and selected and decided
        assert [m["type"] for m in messages] == [
            "LIST_PENDING", "GET_CHALLENGE", "LIST_PENDING", "GET_CHALLENGE", "APPROVE_CHALLENGE"
        ]
        assert b"APPROVED" in output
        server.join(timeout=10)
        assert not server.is_alive() and not errors
    finally:
        os.close(master)
        os.close(slave)


def test_selection_frame_rejects_prequeued_decision_and_flushes(tmp_path):
    if not BINARY.exists():
        pytest.skip("build mayi-executor first")
    path = tmp_path / "approval.sock"
    messages, errors, server = _fake_authority(path, 4)
    master, slave = pty.openpty()
    try:
        rc, _, selected, decided = _console(BINARY, path, master, slave, b"0\napprove\n", None, require_decision=False)
        assert rc != 0 and selected and not decided
        assert [m["type"] for m in messages] == ["LIST_PENDING"]
        rc, output, selected, decided = _console(BINARY, path, master, slave, b"0\n", b"approve\n")
        assert rc == 0 and selected and decided and b"APPROVED" in output
        assert [m["type"] for m in messages] == [
            "LIST_PENDING", "LIST_PENDING", "GET_CHALLENGE", "APPROVE_CHALLENGE"
        ]
        server.join(timeout=10)
        assert not server.is_alive() and not errors
    finally:
        os.close(master)
        os.close(slave)
