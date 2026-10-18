import argparse
import os
import stat
import sys
import time

from .adapters import analyze, AnalysisError
from .executor import ExecutorError, RustExecutorClient
from .operations import Kind, Operation
from .parser import ShellSyntaxError
from .policy import default_policy
from .progress import Waiting

HELP = """Mayi - Controlled Command Authorization

Usage:
  mayi <executable> [arguments ...]
  mayi -- <executable> [arguments ...]
  mayi --queue [--after REQUEST_ID] <executable> [arguments ...]
  mayi --wait [--fail=N] [--fail-instant] REQUEST_ID...
  mayi --status REQUEST_ID
  mayi history [--limit N|--all] [--status STATE] [--request ID] [--since TIME] [--json] [--events]
  mayi inspect|check <legacy shell snippet>
  mayi -u USER inspect|check <legacy shell snippet>

Options:
  -h, --help       Show this local help
  -V, --version    Show this CLI's build version

Only leading Mayi options are parsed; executable arguments stay unchanged.
Use -- to execute a name colliding with an internal command or option.
mayi-approve opens the separate human approval console.
mayi-approve status reads a live approver-role snapshot."""
BROKER_SOCKET = "/run/mayi/request/broker.sock"
BROKER_UID = 23002
TRUSTED_PATH = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
)
MAX_ARG_COUNT = 128
MAX_ARG_LENGTH = 1024
MAX_TOTAL_ARG_BYTES = 2048


def _trusted_file(path):
    canonical = os.path.realpath(path)
    parent = os.path.dirname(canonical)
    if parent not in {os.path.realpath(directory) for directory in TRUSTED_PATH}:
        raise ValueError("executable is outside Mayi's trusted system directories")
    current = "/"
    for part in canonical.strip("/").split("/"):
        current = os.path.join(current, part)
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("executable path is writable or owned by an untrusted user")
    info = os.stat(canonical, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or not info.st_mode & 0o111 or info.st_mode & 0o022:
        raise ValueError("executable must be a root-owned executable in a trusted directory")
    return canonical


def resolve_executable(command):
    if not command or "\0" in command:
        raise ValueError("missing or invalid executable")
    if "/" in command:
        if not command.startswith("/"):
            raise ValueError("relative executable paths are not accepted")
        candidates = [command]
    else:
        candidates = [os.path.join(directory, command) for directory in TRUSTED_PATH]
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return _trusted_file(candidate)
    raise ValueError("executable was not found in Mayi's trusted system directories")


def _legacy_cli(argv):
    if argv and "-u" in argv:
        i = argv.index("-u")
        if i + 1 < len(argv) and (i + 2 >= len(argv) or argv[i + 2] not in ("inspect", "check")):
            user = argv[i + 1]
            command = " ".join(argv[i + 2 :])
            from .identity import resolve_user
            try:
                ident = resolve_user(user)
            except ValueError as e:
                print(f"ERROR: {e}")
                return 2
            print(f"TARGET {ident.name} uid={ident.uid} gid={ident.gid}")
            argv = argv[:i] + ["inspect", command]
    parser = argparse.ArgumentParser(prog="mayi", description="inspect modeled operations")
    parser.add_argument("-u", "--user", dest="user", help="identity for analysis only")
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("inspect", "check"):
        item = sub.add_parser(action)
        item.add_argument("command")
    args = parser.parse_args(argv)
    try:
        operations = analyze(args.command)
    except (ShellSyntaxError, AnalysisError) as error:
        print(f"ERROR: {error}")
        return 2
    if args.user:
        from .identity import resolve_user
        try:
            ident = resolve_user(args.user)
            print(f"TARGET {ident.name} uid={ident.uid} gid={ident.gid}")
        except ValueError as error:
            print(f"ERROR: {error}")
            return 2
    if args.action == "inspect":
        for operation in operations:
            print(operation.display())
        return 0
    decision = default_policy().evaluate(operations)
    print(decision.value)
    if decision.value == "APPROVAL_REQUIRED":
        print("\nOperations:\n")
        for operation in operations:
            print(operation.display())
        print("\n[y] allow once\n[n] deny\n[e] explain")
    return 0


def _write_child_output(result):
    try:
        stdout = bytes.fromhex(result.get("stdout_hex", ""))
        stderr = bytes.fromhex(result.get("stderr_hex", ""))
    except (TypeError, ValueError):
        return False
    sys.stdout.buffer.write(stdout)
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(stderr)
    sys.stderr.buffer.flush()
    if result.get("stdout_truncated") or result.get("stderr_truncated"):
        print("MAYI_OUTPUT_TRUNCATED", file=sys.stderr)
    return True


def _mayi_error(message, code):
    print(message, file=sys.stderr)
    return code


def _execute_request(argv):
    command = argv[0]
    try:
        executable = resolve_executable(command)
        request_argv = [command, *argv[1:]]
        if len(request_argv) > MAX_ARG_COUNT or any("\0" in arg or len(arg.encode()) > MAX_ARG_LENGTH for arg in request_argv):
            raise ValueError("argument count or length exceeds Mayi's limits")
        if sum(len(arg.encode()) for arg in request_argv) > MAX_TOTAL_ARG_BYTES:
            raise ValueError("total argument size exceeds Mayi's limit")
    except (ValueError, OSError, UnicodeError) as error:
        return _mayi_error(f"MAYI_INVALID_REQUEST: {error}", 12)

    client = RustExecutorClient(
        socket_path=BROKER_SOCKET,
        timeout=310,
        expected_broker_uid=BROKER_UID,
    )
    operation = Operation(Kind.EXEC, executable, tuple(request_argv))
    try:
        proposal = client.submit([operation])
    except (ExecutorError, OSError, ValueError) as error:
        text = str(error)
        code = 12 if any(item in text for item in ("INVALID", "UNSUPPORTED", "OPERATION")) else 13 if isinstance(error, PermissionError) or any(item in text for item in ("UNAUTHORIZED", "ROLE_SEPARATION")) else 15
        prefix = "MAYI_INVALID_REQUEST" if code == 12 else "MAYI_AUTHORIZATION_ERROR" if code == 13 else "MAYI_BROKER_ERROR"
        return _mayi_error(f"{prefix}: {text}", code)

    instance = proposal["broker_instance_id"]
    challenge = proposal["challenge_id"]
    digest = proposal["request_digest"]
    print("MAYI_REQUEST_PENDING: waiting for human approval", file=sys.stderr, flush=True)
    with Waiting() as progress:
        while True:
            try:
                status = client.request_status(instance, challenge, digest)["status"]
            except (ExecutorError, OSError) as error:
                progress.stop()
                text = str(error)
                code = 11 if "EXPIRED" in text else 13 if isinstance(error, PermissionError) or any(item in text for item in ("BROKER_INSTANCE", "CHALLENGE_NOT_FOUND", "UNAUTHORIZED")) else 15
                prefix = "MAYI_REQUEST_EXPIRED" if code == 11 else "MAYI_AUTHORIZATION_ERROR" if code == 13 else "MAYI_BROKER_ERROR"
                return _mayi_error(f"{prefix}: {text}", code)
            if status == "PENDING":
                progress.tick()
                time.sleep(0.2)
                continue
            progress.stop()
            if status == "DENIED":
                return _mayi_error("MAYI_APPROVAL_DENIED", 10)
            if status == "EXPLAINED":
                return _mayi_error("MAYI_EXPLAIN_REQUESTED", 20)
            if status == "EXPIRED":
                return _mayi_error("MAYI_REQUEST_EXPIRED", 11)
            if status == "CONSUMED":
                return _mayi_error("MAYI_EXECUTION_UNKNOWN", 16)
            if status != "APPROVED":
                return _mayi_error("MAYI_AUTHORIZATION_ERROR", 13)
            break

    try:
        result = client.consume_approved(instance, challenge, digest)
    except (ExecutorError, OSError, ValueError) as error:
        text = str(error)
        code = 11 if "REQUEST_EXPIRED" in text else 13 if isinstance(error, PermissionError) or any(item in text for item in ("UNAUTHORIZED", "ROLE_SEPARATION")) else 16
        message = "MAYI_REQUEST_EXPIRED" if code == 11 else "MAYI_AUTHORIZATION_ERROR" if code == 13 else "MAYI_EXECUTION_UNKNOWN"
        return _mayi_error(f"{message}: {text}", code)
    execution = result.get("execution")
    if execution == "SUCCEEDED" and result.get("exit_code") == 0:
        if not _write_child_output(result):
            return _mayi_error("MAYI_EXECUTION_UNKNOWN: invalid executor output", 16)
        return 0
    if execution == "FAILED":
        print("MAYI_EXECUTION_FAILED", file=sys.stderr)
        _write_child_output(result)
        return 14
    if execution == "INTERNAL_ERROR":
        return _mayi_error("MAYI_EXECUTOR_INTERNAL_ERROR", 15)
    if execution == "EXECUTION_DISABLED":
        return _mayi_error("MAYI_EXECUTION_DISABLED", 15)
    return _mayi_error("MAYI_EXECUTION_UNKNOWN", 16)


def _exec_operation(argv):
    if not argv:
        raise ValueError("executable required")
    command = argv[0]
    executable = resolve_executable(command)
    request_argv = [command, *argv[1:]]
    if len(request_argv) > MAX_ARG_COUNT or any("\0" in arg or len(arg.encode()) > MAX_ARG_LENGTH for arg in request_argv):
        raise ValueError("argument count or length exceeds Mayi's limits")
    if sum(len(arg.encode()) for arg in request_argv) > MAX_TOTAL_ARG_BYTES:
        raise ValueError("total argument size exceeds Mayi's limit")
    return Operation(Kind.EXEC, executable, tuple(request_argv))


def _queue_cli(argv):
    dependencies = []
    index = 0
    while index < len(argv) and argv[index] == "--after":
        if index + 1 >= len(argv):
            return _mayi_error("MAYI_INVALID_REQUEST: --after requires a request ID", 12)
        dependencies.append(argv[index + 1])
        index += 2
    try:
        operation = _exec_operation(argv[index:])
        client = RustExecutorClient(socket_path=BROKER_SOCKET, timeout=5, expected_broker_uid=BROKER_UID)
        result = client.queue([operation], dependencies)
    except PermissionError as error:
        return _mayi_error(f"MAYI_AUTHORIZATION_ERROR: {error}", 13)
    except (ValueError, OSError, UnicodeError) as error:
        return _mayi_error(f"MAYI_INVALID_REQUEST: {error}", 12)
    except ExecutorError as error:
        text = str(error)
        code = 13 if any(item in text for item in ("UNAUTHORIZED", "OWNER_MISMATCH")) else 12 if any(item in text for item in ("INVALID", "DEPENDENCY", "OPERATION")) else 15
        return _mayi_error(f"MAYI_QUEUE_ERROR: {text}", code)
    print(result["request_id"], flush=True)
    return 0


_TERMINAL_QUEUE_STATES = {"SUCCEEDED", "FAILED", "DENIED", "EXPLAIN_REQUESTED", "EXPIRED", "EXECUTION_UNKNOWN", "BLOCKED"}


def _queue_status_line(request_id, result):
    state = result.get("state", "EXECUTION_UNKNOWN")
    code = result.get("mayi_result")
    child = result.get("child_exit_status")
    if state == "BLOCKED" and result.get("blocking_dependency"):
        return f"{request_id} {state} mayi={code if code is not None else '-'} child={child if child is not None else '-'} dependency={result['blocking_dependency']}"
    return f"{request_id} {state} mayi={code if code is not None else '-'} child={child if child is not None else '-'}"


def _queue_status(client, request_id):
    try:
        return client.queue_status(request_id), None
    except (ExecutorError, OSError, ValueError) as error:
        text = str(error)
        code = 13 if "UNAUTHORIZED" in text else 16 if any(x in text for x in ("NOT_FOUND", "BROKER_INSTANCE")) else 15
        return None, (text, code)


def _wait_cli(argv):
    failure_budget = 0
    fail_instant = False
    ids = []
    for item in argv:
        if item.startswith("--fail="):
            try:
                failure_budget = int(item.split("=", 1)[1])
                if failure_budget < 0:
                    raise ValueError
            except ValueError:
                return _mayi_error("MAYI_INVALID_REQUEST: --fail must be a nonnegative integer", 12)
        elif item == "--fail-instant":
            fail_instant = True
        elif item.startswith("--"):
            return _mayi_error(f"MAYI_INVALID_REQUEST: unknown wait option {item}", 12)
        else:
            ids.append(item)
    if not ids or any(not isinstance(item, str) or len(item) != 35 or not item.startswith("rq_") or any(c not in "0123456789abcdef" for c in item[3:]) for item in ids) or len(set(ids)) != len(ids):
        return _mayi_error("MAYI_INVALID_REQUEST: --wait requires unique request IDs", 12)
    client = RustExecutorClient(socket_path=BROKER_SOCKET, timeout=5, expected_broker_uid=BROKER_UID)
    known = {}
    budget_exceeded = False
    while True:
        failures = 0
        terminal_count = 0
        for request_id in ids:
            result, error = _queue_status(client, request_id)
            if error:
                return _mayi_error(f"MAYI_WAIT_ERROR: {error[0]}", error[1])
            known[request_id] = result
            state = result["state"]
            if state in _TERMINAL_QUEUE_STATES:
                terminal_count += 1
                if state != "SUCCEEDED":
                    failures += 1
            if fail_instant and failures > failure_budget:
                budget_exceeded = True
                break
        if budget_exceeded or terminal_count == len(ids):
            break
        time.sleep(1)
    for request_id in ids:
        result = known.get(request_id)
        print(_queue_status_line(request_id, result) if result is not None else f"{request_id} NOT_OBSERVED mayi=- child=-")
    failures = sum(known[item]["state"] in _TERMINAL_QUEUE_STATES and known[item]["state"] != "SUCCEEDED" for item in known)
    return 1 if budget_exceeded or failures > failure_budget else 0


def _status_cli(argv):
    if len(argv) != 1:
        return _mayi_error("MAYI_INVALID_REQUEST: --status requires one request ID", 12)
    client = RustExecutorClient(socket_path=BROKER_SOCKET, timeout=5, expected_broker_uid=BROKER_UID)
    result, error = _queue_status(client, argv[0])
    if error:
        return _mayi_error(f"MAYI_STATUS_ERROR: {error[0]}", error[1])
    print(_queue_status_line(argv[0], result))
    return 0


def main(argv=None):
    argv = list(argv) if argv is not None else sys.argv[1:]
    # Separator wins before any metadata/internal-command dispatch.
    if argv and argv[0] == "--":
        if len(argv) == 1:
            return _mayi_error("MAYI_CLI_ERROR: executable required after --", 12)
        return _execute_request(argv[1:])
    if not argv:
        print(HELP)
        return 2
    from .cli_metadata import dispatch_metadata
    metadata = dispatch_metadata(argv, "mayi", HELP)
    if metadata is not None:
        return metadata
    if argv[0] == "history":
        from .history import main as history_main
        return history_main(argv[1:])
    if argv and argv[0] == "--queue":
        return _queue_cli(argv[1:])
    if argv and argv[0] == "--wait":
        return _wait_cli(argv[1:])
    if argv and argv[0] == "--status":
        return _status_cli(argv[1:])
    if argv[0] in ("inspect", "check") or argv[0] == "-u":
        return _legacy_cli(argv)
    if argv[0].startswith("-"):
        return _mayi_error("MAYI_CLI_ERROR: unknown leading option (see --help); use -- for executable names beginning with a hyphen", 12)
    return _execute_request(argv)


if __name__ == "__main__":
    raise SystemExit(main())
