import os
import sys

EXECUTOR = "/usr/bin/mayi-executor"
BROKER_UID = "23002"
SOCKET = "/run/mayi/approval/broker.sock"


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'status':
        from .approval_status import main as status_main
        raise SystemExit(status_main(sys.argv[2:]))
    if len(sys.argv) != 1:
        print("Usage: mayi-approve | mayi-approve status [--json] [--watch] [--interval SECONDS]", file=sys.stderr)
        raise SystemExit(2)
    os.execv(
        EXECUTOR,
        [
            EXECUTOR,
            "--approval-console",
            "--approval-socket",
            SOCKET,
            "--broker-uid",
            BROKER_UID,
        ],
    )
