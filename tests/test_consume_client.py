import json
import os
import socket
import threading

import pytest

from mayi.executor import ExecutorError, RustExecutorClient


def _recv_exact(conn, size):
    data = bytearray()
    while len(data) < size:
        part = conn.recv(size - len(data))
        if not part:
            raise EOFError("truncated frame")
        data.extend(part)
    return bytes(data)


def _server(path, response, received):
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)

    def serve():
        with listener:
            conn, _ = listener.accept()
            with conn:
                size = int.from_bytes(_recv_exact(conn, 4), "big")
                received.append(json.loads(_recv_exact(conn, size)))
                payload = json.dumps(response, separators=(",", ":")).encode()
                conn.sendall(len(payload).to_bytes(4, "big") + payload)

    thread = threading.Thread(target=serve)
    thread.start()
    return thread


def test_consume_client_sends_only_broker_correlation(tmp_path):
    instance, challenge, digest = "a" * 48, "b" * 48, "c" * 64
    response = {
        "ok": True,
        "protocol": 5,
        "response_to": "CONSUME_APPROVED",
        "status": "CONSUMED",
        "state": "CONSUMED",
        "execution": "EXECUTION_DISABLED",
        "broker_instance_id": instance,
        "challenge_id": challenge,
        "request_digest": digest,
    }
    received = []
    path = tmp_path / "broker.sock"
    thread = _server(path, response, received)
    result = RustExecutorClient(socket_path=str(path), expected_broker_uid=os.getuid()).consume_approved(instance, challenge, digest)
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert result["execution"] == "EXECUTION_DISABLED"
    assert received == [{
        "type": "CONSUME_APPROVED",
        "protocol": 5,
        "broker_instance_id": instance,
        "challenge_id": challenge,
        "request_digest": digest,
    }]


def test_queue_client_sends_dependencies_and_accepts_only_broker_request_id(tmp_path):
    request_id = "rq_" + "a" * 32
    response = {"ok": True, "protocol": 5, "response_to": "QUEUE_REQUEST", "type": "QUEUE_RESPONSE", "request_id": request_id}
    received = []
    path = tmp_path / "broker.sock"
    thread = _server(path, response, received)
    from mayi.operations import Kind, Operation
    operation = Operation(Kind.EXEC, "/usr/bin/true", ("true",))
    result = RustExecutorClient(socket_path=str(path), expected_broker_uid=os.getuid()).queue([operation], ["rq_" + "b" * 32])
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert result["request_id"] == request_id
    assert received[0]["type"] == "QUEUE_REQUEST"
    assert received[0]["dependencies"] == ["rq_" + "b" * 32]
    assert received[0]["operations"] == [{"type": "exec", "executable": "/usr/bin/true", "argv": ["true"]}]


def test_queue_status_client_validates_request_and_state(tmp_path):
    request_id = "rq_" + "c" * 32
    response = {"ok": True, "protocol": 5, "response_to": "GET_QUEUE_STATUS", "request_id": request_id, "state": "SUCCEEDED", "mayi_result": 0, "child_exit_status": 0}
    received = []
    path = tmp_path / "broker.sock"
    thread = _server(path, response, received)
    result = RustExecutorClient(socket_path=str(path), expected_broker_uid=os.getuid()).queue_status(request_id)
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert result["state"] == "SUCCEEDED"
    assert received == [{"type": "GET_QUEUE_STATUS", "protocol": 5, "request_id": request_id}]


def test_consume_client_rejects_mismatched_result(tmp_path):
    instance, challenge, digest = "a" * 48, "b" * 48, "c" * 64
    response = {
        "ok": True,
        "protocol": 5,
        "response_to": "CONSUME_APPROVED",
        "status": "CONSUMED",
        "state": "CONSUMED",
        "execution": "EXECUTION_DISABLED",
        "broker_instance_id": instance,
        "challenge_id": challenge,
        "request_digest": "d" * 64,
    }
    received = []
    path = tmp_path / "broker.sock"
    thread = _server(path, response, received)
    with pytest.raises(ExecutorError, match="correlation/status mismatch"):
        RustExecutorClient(socket_path=str(path), expected_broker_uid=os.getuid()).consume_approved(instance, challenge, digest)
    thread.join(timeout=2)
    assert not thread.is_alive()
