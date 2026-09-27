import os
import sys

EXECUTOR = "/usr/bin/mayi-executor"
BROKER_UID = "23002"
SOCKET = "/run/mayi/approval/broker.sock"


def main():
    if len(sys.argv) != 1:
        print("Usage: mayi-approve (no options are accepted)", file=sys.stderr)
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
