import os
import sys

EXECUTOR = "/usr/bin/mayi-executor"
BROKER_UID = "23002"
SOCKET = "/run/mayi/approval/broker.sock"


HELP = """Mayi - Human Approval Console

Usage:
  mayi-approve
  mayi-approve status [--json] [--details] [--watch] [--interval SECONDS]
  mayi-approve status --watch --plain
  mayi-approve status --preflight [--json]

Options:
  -h, --help       Show this local help
  -V, --version    Show this CLI's build version

No arguments opens the PAM-authenticated interactive approval console.
status is a read-only live broker query under the existing approver role.
Metadata options do not connect to the broker or authenticate."""

def main():
    from .cli_metadata import dispatch_metadata
    metadata = dispatch_metadata(sys.argv[1:], "mayi-approve", HELP)
    if metadata is not None:
        raise SystemExit(metadata)
    if len(sys.argv) > 1 and sys.argv[1] == 'status':
        from .approval_status import main as status_main
        raise SystemExit(status_main(sys.argv[2:]))
    if len(sys.argv) != 1:
        print("Usage: mayi-approve | mayi-approve status --help", file=sys.stderr)
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
