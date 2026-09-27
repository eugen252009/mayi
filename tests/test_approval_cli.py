import sys

import pytest

from mayi import approval_cli


def test_approval_launcher_rejects_all_arguments_without_echoing_them(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["mayi-approve", "--password"])
    called = []
    monkeypatch.setattr(approval_cli.os, "execv", lambda *args: called.append(args))

    with pytest.raises(SystemExit) as error:
        approval_cli.main()

    assert error.value.code == 2
    assert called == []
    output = capsys.readouterr()
    assert "Usage: mayi-approve" in output.err
    assert "--password" not in output.err


def test_approval_launcher_execs_only_fixed_noncredential_arguments(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["mayi-approve"])
    calls = []
    monkeypatch.setattr(approval_cli.os, "execv", lambda *args: calls.append(args))

    approval_cli.main()

    assert calls == [
        (
            "/usr/bin/mayi-executor",
            [
                "/usr/bin/mayi-executor",
                "--approval-console",
                "--approval-socket",
                "/run/mayi/approval/broker.sock",
                "--broker-uid",
                "23002",
            ],
        )
    ]
