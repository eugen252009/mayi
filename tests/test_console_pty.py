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
BINARY = Path(os.environ.get("MAYI_EXECUTOR_BIN", "executor/target/debug/mayi-executor"))


def _read_exact(conn, size):
    data = bytearray()
    while len(data) < size:
        part = conn.recv(size - len(data))
        if not part:
            raise EOFError("short frame")
        data.extend(part)
    return bytes(data)


def _row(index, dependency=None):
    request_id = "rq_" + format(index + 1, "032x")
    challenge = format(index + 1, "048x")
    digest = format(index + 1, "064x")
    return {
        "request_id": request_id,
        "challenge_id": challenge,
        "request_digest": digest,
        "requester_uid": 1001,
        "expires_at": int(time.time()) + 1000,
        "queue_state": "PENDING_APPROVAL",
        "dependencies": [] if dependency is None else ["rq_" + format(i + 1, "032x") for i in (dependency if isinstance(dependency, list) else [dependency])],
        "operations": [{"type": "exec", "executable": "/usr/bin/true", "argv": ["true"]}],
        "blocking_dependency": None,
    }


def _fake_authority(path, rows):
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen()
    listener.settimeout(0.2)
    pending = [dict(row) for row in rows]
    messages = []
    errors = []
    stopped = threading.Event()

    def serve():
        try:
            while not stopped.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                with conn:
                    size = int.from_bytes(_read_exact(conn, 4), "big")
                    msg = json.loads(_read_exact(conn, size))
                    messages.append(msg)
                    ty = msg["type"]
                    if ty == "LIST_PENDING":
                        active = [row for row in pending if row["queue_state"] == "PENDING_APPROVAL"]
                        response = {"ok": True, "protocol": 5, "response_to": ty,
                                    "broker_instance_id": BROKER, "pending": pending if active else []}
                    elif ty == "GET_CHALLENGE":
                        response = {"ok": True, "protocol": 5, "response_to": ty,
                                    "type": "CHALLENGE_VIEW", "status": "DISPLAYED",
                                    "state": "PENDING_APPROVAL", "broker_instance_id": BROKER,
                                    "challenge_id": msg["challenge_id"],
                                    "request_digest": next(r["request_digest"] for r in pending if r["challenge_id"] == msg["challenge_id"]),
                                    "view_id": format(len(messages), "048x"),
                                    "view_expires_at": int(time.time()) + 50,
                                    "rendered": "not displayed by queue console"}
                    else:
                        status, state = {"APPROVE_CHALLENGE": ("APPROVED", "WAITING_DEPENDENCY"),
                                         "DENY_CHALLENGE": ("DENIED", "DENIED"),
                                         "EXPLAIN_CHALLENGE": ("EXPLAINED", "EXPLAIN_REQUESTED")}[ty]
                        for row in pending:
                            if row["challenge_id"] == msg["challenge_id"]:
                                row["queue_state"] = state
                        response = {"ok": True, "protocol": 5, "response_to": ty,
                                    "status": status, "authorized": ty == "APPROVE_CHALLENGE",
                                    "broker_instance_id": BROKER,
                                    "challenge_id": msg["challenge_id"],
                                    "request_digest": msg["request_digest"],
                                    "view_id": msg["view_id"]}
                    payload = json.dumps(response, separators=(",", ":")).encode()
                    conn.sendall(len(payload).to_bytes(4, "big") + payload)
        except Exception as exc:
            if not stopped.is_set():
                errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return messages, pending, errors, stopped, thread


def _read_until(master, proc, output, needle, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.05)
        if ready:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                chunk = b""
            if chunk:
                output.extend(chunk)
                if needle in output:
                    return
        if proc.poll() is not None:
            break
    raise AssertionError(f"did not see {needle!r}; output={bytes(output)!r}; rc={proc.poll()}")


def _read_until_count(master, proc, output, needle, count, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and output.count(needle) < count:
        ready, _, _ = select.select([master], [], [], 0.05)
        if ready:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                chunk = b""
            if chunk:
                output.extend(chunk)
        if proc.poll() is not None:
            break
    assert output.count(needle) >= count, f"did not see {needle!r} {count} times; output={bytes(output)!r}; rc={proc.poll()}"


def _start_console(path):
    master, slave = pty.openpty()
    proc = subprocess.Popen(
        [str(BINARY), "--approval-console", "--approval-socket", str(path), "--broker-uid", str(os.getuid())],
        stdin=slave, stdout=slave, stderr=slave, close_fds=True,
    )
    os.close(slave)
    return proc, master, bytearray()


def _finish(proc, master, output):
    if proc.poll() is None:
        os.write(master, b"q\n")
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait(timeout=5)
    assert proc.returncode == 0, bytes(output).decode("utf-8", "replace")


@pytest.fixture(autouse=True)
def require_binary():
    if not BINARY.exists():
        pytest.skip("build mayi-executor first")


def test_console_persists_after_approval_and_shows_exact_argv(tmp_path):
    path = tmp_path / "approval.sock"
    messages, pending, errors, stopped, server = _fake_authority(path, [_row(0)])
    proc, master, output = _start_console(path)
    try:
        _read_until(master, proc, output, b"[a] allow all")
        assert b"/usr/bin/true" in output and b'argv[0] "true"' in output
        os.write(master, b"a\n")
        _read_until(master, proc, output, b"Approved: 0")
        assert proc.poll() is None, "approval console exited after one decision"
        _read_until(master, proc, output, b"Waiting for Mayi requests...")
        _finish(proc, master, output)
        assert [msg["type"] for msg in messages if msg["type"] != "LIST_PENDING"] == ["GET_CHALLENGE", "APPROVE_CHALLENGE"]
        assert not errors
    finally:
        stopped.set()
        if proc.poll() is None:
            proc.terminate(); proc.wait(timeout=5)
        os.close(master)
        server.join(timeout=2)


@pytest.mark.parametrize(("input_frame", "selection", "decision_type"), [
    (b"0\n", None, "APPROVE_CHALLENGE"),
    (b"d\n", b"all\n", "DENY_CHALLENGE"),
    (b"f\n", b"all\n", "EXPLAIN_CHALLENGE"),
])
def test_asdf_and_numeric_controls_are_one_shot(input_frame, selection, decision_type, tmp_path):
    path = tmp_path / "approval.sock"
    messages, _, errors, stopped, server = _fake_authority(path, [_row(0)])
    proc, master, output = _start_console(path)
    try:
        _read_until(master, proc, output, b"[a] allow all")
        os.write(master, input_frame)
        if selection:
            prompt = b"Deny [all or indices]:" if decision_type == "DENY_CHALLENGE" else b"Follow up on [all or indices]:"
            _read_until(master, proc, output, prompt)
            os.write(master, selection)
        acknowledgement = {"APPROVE_CHALLENGE": b"Approved: 0", "DENY_CHALLENGE": b"Denied: 0", "EXPLAIN_CHALLENGE": b"Follow-up requested: 0"}[decision_type]
        _read_until(master, proc, output, acknowledgement)
        _finish(proc, master, output)
        assert [m["type"] for m in messages if m["type"] in {"APPROVE_CHALLENGE", "DENY_CHALLENGE", "EXPLAIN_CHALLENGE"}] == [decision_type]
        assert not errors
    finally:
        stopped.set()
        if proc.poll() is None:
            proc.terminate(); proc.wait(timeout=5)
        os.close(master)
        server.join(timeout=2)


def test_dependency_graph_partial_and_order_independent_approval(tmp_path):
    path = tmp_path / "approval.sock"
    rows = [_row(0), _row(1, 0), _row(2, 1)]
    messages, pending, errors, stopped, server = _fake_authority(path, rows)
    proc, master, output = _start_console(path)
    try:
        _read_until(master, proc, output, b"[a] allow all")
        assert output.count(b"     \xe2\x86\x93") >= 2
        os.write(master, b"210\n")
        _read_until(master, proc, output, b"Approved: 0 1 2")
        decisions = [m["challenge_id"] for m in messages if m["type"] == "APPROVE_CHALLENGE"]
        assert decisions == [rows[i]["challenge_id"] for i in (0, 1, 2)]
        _finish(proc, master, output)
        assert not errors
    finally:
        stopped.set()
        if proc.poll() is None:
            proc.terminate(); proc.wait(timeout=5)
        os.close(master)
        server.join(timeout=2)


def test_branching_dag_displays_both_dependencies_in_topological_order(tmp_path):
    path = tmp_path / "approval.sock"
    rows = [_row(0), _row(1), _row(2, [0, 1])]
    messages, _, errors, stopped, server = _fake_authority(path, rows)
    proc, master, output = _start_console(path)
    try:
        _read_until(master, proc, output, b"[a] allow all")
        assert b"Commands: 3" in output and b"after: 0,1" in output
        os.write(master, b"210\n")
        _read_until(master, proc, output, b"Approved: 0 1 2")
        decisions = [m["challenge_id"] for m in messages if m["type"] == "APPROVE_CHALLENGE"]
        assert decisions == [rows[i]["challenge_id"] for i in (0, 1, 2)]
        _finish(proc, master, output)
        assert not errors
    finally:
        stopped.set()
        if proc.poll() is None:
            proc.terminate(); proc.wait(timeout=5)
        os.close(master)
        server.join(timeout=2)


def test_partial_approval_selects_only_pending_commands(tmp_path):
    path = tmp_path / "approval.sock"
    rows = [_row(0), _row(1, 0), _row(2, 1)]
    messages, pending, errors, stopped, server = _fake_authority(path, rows)
    proc, master, output = _start_console(path)
    try:
        _read_until(master, proc, output, b"[a] allow all")
        os.write(master, b"0\n")
        _read_until(master, proc, output, b"Approved: 0")
        pending[0]["queue_state"] = "SUCCEEDED"
        _read_until_count(master, proc, output, b"Commands: 3", 2)
        os.write(master, b"1\n")
        _read_until(master, proc, output, b"Approved: 1")
        assert [m["challenge_id"] for m in messages if m["type"] == "APPROVE_CHALLENGE"] == [rows[0]["challenge_id"], rows[1]["challenge_id"]]
        _finish(proc, master, output)
        assert not errors
    finally:
        stopped.set()
        if proc.poll() is None:
            proc.terminate(); proc.wait(timeout=5)
        os.close(master)
        server.join(timeout=2)


def test_skip_other_set_then_skipped_set_resurfaces(tmp_path):
    path = tmp_path / "approval.sock"
    rows = [_row(0), _row(1)]
    messages, _, errors, stopped, server = _fake_authority(path, rows)
    proc, master, output = _start_console(path)
    try:
        _read_until(master, proc, output, b"[a] allow all")
        os.write(master, b"s\n")
        _read_until_count(master, proc, output, b"[a] allow all", 2)
        os.write(master, b"a\n")
        _read_until_count(master, proc, output, b"Approved: 0", 1)
        _read_until_count(master, proc, output, b"[a] allow all", 3)
        os.write(master, b"a\n")
        _read_until_count(master, proc, output, b"Approved: 0", 2)
        decisions = [m["challenge_id"] for m in messages if m["type"] == "APPROVE_CHALLENGE"]
        assert sorted(decisions) == sorted(row["challenge_id"] for row in rows)
        _finish(proc, master, output)
        assert not errors
    finally:
        stopped.set()
        if proc.poll() is None:
            proc.terminate(); proc.wait(timeout=5)
        os.close(master)
        server.join(timeout=2)


def test_new_request_arrival_is_printed_while_console_waits(tmp_path):
    path = tmp_path / "approval.sock"
    rows = [_row(0)]
    messages, pending, errors, stopped, server = _fake_authority(path, rows)
    proc, master, output = _start_console(path)
    try:
        _read_until(master, proc, output, b"request ID: rq_" + format(1, "032x").encode())
        pending.append(_row(1))
        _read_until(master, proc, output, b"request ID: rq_" + format(2, "032x").encode())
        os.write(master, b"a\n")
        _read_until_count(master, proc, output, b"Approved: 0", 1)
        _read_until_count(master, proc, output, b"[a] allow all", 3)
        os.write(master, b"a\n")
        _read_until_count(master, proc, output, b"Approved: 0", 2)
        decisions = [m["challenge_id"] for m in messages if m["type"] == "APPROVE_CHALLENGE"]
        assert sorted(decisions) == sorted(row["challenge_id"] for row in pending)
        _finish(proc, master, output)
        assert not errors
    finally:
        stopped.set()
        if proc.poll() is None:
            proc.terminate(); proc.wait(timeout=5)
        os.close(master)
        server.join(timeout=2)
