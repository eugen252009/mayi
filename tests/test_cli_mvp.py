from mayi import cli
from mayi.operations import Kind
from mayi.protocol import canonical_operations


def test_resolves_using_fixed_trusted_path_and_rejects_untrusted_paths(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    assert cli.resolve_executable("printf") == "/usr/bin/printf"
    for value in ("./printf", str(tmp_path / "evil"), "/tmp/evil"):
        try:
            cli.resolve_executable(value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted untrusted executable {value}")


def test_exec_proposal_uses_structured_argv_with_literal_metacharacters():
    operation = cli.Operation(
        Kind.EXEC,
        "/usr/bin/printf",
        ("printf", "%s", "; touch /tmp/pwned"),
    )
    assert canonical_operations([operation]) == [{
        "type": "exec",
        "executable": "/usr/bin/printf",
        "argv": ["printf", "%s", "; touch /tmp/pwned"],
    }]


def test_deny_and_explain_never_consume_or_execute(monkeypatch, capsys):
    class FakeClient:
        next_status = "DENIED"
        consumed = 0

        def __init__(self, **kwargs):
            pass

        def submit(self, operations):
            assert operations[0].kind is Kind.EXEC
            return {"broker_instance_id": "a" * 48, "challenge_id": "b" * 48, "request_digest": "c" * 64}

        def request_status(self, *_):
            return {"status": self.next_status}

        def consume_approved(self, *_):
            self.consumed += 1
            raise AssertionError("terminal non-approval attempted consumption")

    monkeypatch.setattr(cli, "RustExecutorClient", FakeClient)
    assert cli.main(["/usr/bin/true"]) == 10
    assert "MAYI_APPROVAL_DENIED" in capsys.readouterr().err
    FakeClient.next_status = "EXPLAINED"
    assert cli.main(["/usr/bin/true"]) == 20
    assert "MAYI_EXPLAIN_REQUESTED" in capsys.readouterr().err
    assert FakeClient.consumed == 0


def test_authorization_and_internal_errors_have_distinct_exit_codes(monkeypatch, capsys):
    class FakeClient:
        error = cli.ExecutorError("UNAUTHORIZED_REQUESTER: not a member")

        def __init__(self, **kwargs):
            pass

        def submit(self, operations):
            raise self.error

    monkeypatch.setattr(cli, "RustExecutorClient", FakeClient)
    assert cli.main(["/usr/bin/id"]) == 13
    assert "MAYI_AUTHORIZATION_ERROR" in capsys.readouterr().err
    FakeClient.error = cli.ExecutorError("INTERNAL_ERROR: NSS lookup failed")
    assert cli.main(["/usr/bin/id"]) == 15
    assert "MAYI_BROKER_ERROR" in capsys.readouterr().err
    FakeClient.error = PermissionError(13, "Permission denied")
    assert cli.main(["/usr/bin/id"]) == 13
    assert "MAYI_AUTHORIZATION_ERROR" in capsys.readouterr().err


def test_queue_stdout_is_only_opaque_broker_request_id(monkeypatch, capsys):
    request_id = "rq_" + "a" * 32
    class FakeClient:
        def __init__(self, **kwargs):
            pass
        def queue(self, operations, dependencies):
            assert operations[0].kind is Kind.EXEC
            assert dependencies == ["rq_" + "b" * 32]
            return {"request_id": request_id}
    monkeypatch.setattr(cli, "RustExecutorClient", FakeClient)
    assert cli.main(["--queue", "--after", "rq_" + "b" * 32, "/usr/bin/true"]) == 0
    captured = capsys.readouterr()
    assert captured.out == request_id + "\n"
    assert captured.err == ""


def test_wait_failure_budget_and_fail_instant(monkeypatch, capsys):
    first, second = "rq_" + "a" * 32, "rq_" + "b" * 32
    class FakeClient:
        calls = []
        def __init__(self, **kwargs):
            pass
        def queue_status(self, request_id):
            self.calls.append(request_id)
            if request_id == first:
                return {"request_id": first, "state": "FAILED", "mayi_result": 14, "child_exit_status": 1}
            return {"request_id": second, "state": "SUCCEEDED", "mayi_result": 0, "child_exit_status": 0}
    monkeypatch.setattr(cli, "RustExecutorClient", FakeClient)
    assert cli.main(["--wait", "--fail=0", first, second]) == 1
    assert "FAILED mayi=14 child=1" in capsys.readouterr().out
    assert cli.main(["--wait", "--fail=1", first, second]) == 0
    capsys.readouterr()
    FakeClient.calls.clear()
    assert cli.main(["--wait", "--fail=0", "--fail-instant", first, second]) == 1
    output = capsys.readouterr().out
    assert "NOT_OBSERVED" in output
    assert FakeClient.calls == [first]


def test_success_and_execution_failure_are_distinct(monkeypatch, capsys):
    class FakeClient:
        outcome = {"execution": "SUCCEEDED", "exit_code": 0, "stdout_hex": "41", "stderr_hex": ""}

        def __init__(self, **kwargs):
            pass

        def submit(self, operations):
            return {"broker_instance_id": "a" * 48, "challenge_id": "b" * 48, "request_digest": "c" * 64}

        def request_status(self, *_):
            return {"status": "APPROVED"}

        def consume_approved(self, *_):
            return self.outcome

    monkeypatch.setattr(cli, "RustExecutorClient", FakeClient)
    assert cli.main(["/usr/bin/printf", "A"]) == 0
    assert capsys.readouterr().out == "A"
    FakeClient.outcome = {"execution": "FAILED", "exit_code": 1, "stdout_hex": "", "stderr_hex": ""}
    assert cli.main(["/usr/bin/false"]) == 14
    assert "MAYI_EXECUTION_FAILED" in capsys.readouterr().err
