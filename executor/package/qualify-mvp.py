#!/usr/bin/env python3
import base64
import json
import os
import pty
import select
import secrets
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

NAME = os.environ.get("MAYI_TEST_CONTAINER")
MODE = os.environ.get("MAYI_TEST_MODE", "fresh")
TARGET_VERSION = os.environ.get("MAYI_TARGET_VERSION", "0.4.1")
# Qualification-only random values stay in process memory and disposable containers.
APPROVER_PASSWORD = secrets.token_urlsafe(32)
WRONG_PASSWORD = secrets.token_urlsafe(32)
SYSTEMD_MODE = os.environ.get("MAYI_TEST_SYSTEMD", "0") == "1"
APT_MODE = os.environ.get("MAYI_TEST_APT", "0") == "1"
KEEP_PACKAGE = os.environ.get("MAYI_TEST_KEEP_PACKAGE", "0") == "1"
if not NAME or MODE not in {"fresh", "upgrade", "upgrade020", "upgrade021", "upgrade022", "upgrade030", "upgrade031", "upgrade032", "upgrade040", "upgrade041"}:
    raise SystemExit("MAYI_TEST_CONTAINER and MAYI_TEST_MODE=fresh|upgrade|upgrade020|upgrade021|upgrade022|upgrade030|upgrade031|upgrade032|upgrade040|upgrade041 are required")
if TARGET_VERSION not in {"0.2.1", "0.2.2", "0.3.0", "0.3.1", "0.3.2", "0.4.0", "0.4.1", "0.4.1-1"}:
    raise SystemExit("MAYI_TARGET_VERSION must be 0.2.1, 0.2.2, 0.3.0, 0.3.1, 0.3.2, 0.4.0, 0.4.1, or 0.4.1-1")

USERS = {
    "both": (1000, 1000, (23011, 23013)),
    "requester": (1001, 1001, (23011,)),
    "approver": (1002, 1002, (23013,)),
    "unauthorized": (1003, 1003, ()),
    "primary_requester": (1004, 23011, ()),
    "primary_approver": (1005, 23013, ()),
}


def docker(*args, check=True, timeout=30, input=None):
    command = ["docker", "exec"]
    if input is not None:
        command.append("-i")
    result = subprocess.run([*command, NAME, *map(str, args)], input=input,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"docker exec {args!r} failed ({result.returncode}): {result.stderr.decode(errors='replace')}")
    return result


def command_path(name):
    for directory in ("/usr/bin", "/bin"):
        path = f"{directory}/{name}"
        if docker("test", "-x", path, check=False).returncode == 0:
            return path
    raise RuntimeError(f"required system command is unavailable: {name}")


def setpriv_args(uid, gid, groups, no_new_privs=True):
    args = ["/usr/bin/setpriv", f"--reuid={uid}", f"--regid={gid}"]
    if no_new_privs:
        args.insert(1, "--no-new-privs")
    if groups:
        args.append("--groups=" + ",".join(map(str, groups)))
    else:
        args.append("--clear-groups")
    return args


def docker_as(uid, gid, groups, *args, tty=False, input=None, timeout=30, check=True):
    cmd = ["docker", "exec"]
    if tty:
        cmd.append("-it")
    elif input is not None:
        cmd.append("-i")
    cmd += [NAME, *setpriv_args(uid, gid, groups), *map(str, args)]
    return subprocess.run(cmd, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=check)


def journal_events(prefix):
    result = docker("journalctl", "-u", "mayi-privileged-executor.service", "-o", "cat", "--no-pager")
    return sum(line.startswith(prefix) for line in result.stdout.splitlines())


def count_started():
    if SYSTEMD_MODE:
        return journal_events(b"event=EXECUTION_STARTED ")
    result = docker("sh", "-c", "grep -c '^event=EXECUTION_STARTED ' /tmp/executor.log || true")
    return int(result.stdout.strip() or b"0")


def wait_text(proc, stream, needle, timeout=20):
    data = bytearray()
    deadline = time.monotonic() + timeout
    fd = stream.fileno()
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            data.extend(chunk)
            if needle in data:
                return bytes(data)
        if proc.poll() is not None:
            break
    raise RuntimeError(f"timed out waiting for {needle!r}; got {data!r}")


def approve_actions(actions, identity="both", on_decision=None):
    uid, gid, groups = USERS[identity]
    master, slave = pty.openpty()
    proc = subprocess.Popen(
        ["docker", "exec", "-it", "--env", "TERM=xterm-256color", NAME, *setpriv_args(uid, gid, groups, no_new_privs=TARGET_VERSION not in {"0.4.0", "0.4.1", "0.4.1-1"}), "/usr/bin/mayi-approve"],
        stdin=slave, stdout=slave, stderr=slave, close_fds=True,
    )
    os.close(slave)
    output = bytearray()
    def wait_marker(marker, count=1):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and output.count(marker) < count and proc.poll() is None:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    output.extend(os.read(master, 4096))
                except OSError:
                    break
        if output.count(marker) < count:
            raise RuntimeError(f"approval console missed {marker!r}: {output.decode(errors='replace')}")
    try:
        controls = 0
        acknowledgements = {}
        if TARGET_VERSION in {"0.4.0", "0.4.1", "0.4.1-1"}:
            wait_marker(b"Password:")
            os.write(master, APPROVER_PASSWORD.encode() + b"\n")
        wait_marker(b"[a] allow all")
        controls = 1
        for action_index, (action, subset) in enumerate(actions):
            action = {"y": "a", "n": "d", "e": "f"}.get(action, action)
            os.write(master, action.encode() + b"\n")
            if action in {"d", "f"}:
                prompt = b"Deny [all or indices]:" if action == "d" else b"Follow up on [all or indices]:"
                wait_marker(prompt)
                os.write(master, (subset or "all").encode() + b"\n")
            if action == "s":
                wait_marker(b"[a] allow all", controls + 1)
                controls += 1
            else:
                marker = {"a": b"Approved:", "d": b"Denied:", "f": b"Follow-up requested:"}.get(action, b"Approved:")
                acknowledgements[marker] = acknowledgements.get(marker, 0) + 1
                wait_marker(marker, acknowledgements[marker])
                if on_decision is not None:
                    on_decision(action_index)
                if action != actions[-1][0] and len(actions) > 1:
                    wait_marker(b"[a] allow all", controls + 1)
                    controls += 1
        if any(action == "s" for action, _ in actions):
            wait_marker(b"[a] allow all", controls + 1)
        os.write(master, b"q\n")
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.terminate(); proc.wait(timeout=5)
            raise RuntimeError(f"persistent approval console did not quit: {output.decode(errors='replace')}")
        if proc.returncode != 0:
            raise RuntimeError(f"approval console failed: rc={proc.returncode}, output={output.decode(errors='replace')}")
        if TARGET_VERSION in {"0.4.0", "0.4.1", "0.4.1-1"}:
            assert output.count(b"Password:") == 1 and b"Authenticated." not in output, output
            assert b"APPROVAL_AUTH_SUCCESS" not in output
            assert APPROVER_PASSWORD.encode() not in output, "PAM password was echoed to the terminal"
            assert output.count(b"\x1b[2J\x1b[H") == sum(action != "s" for action, _ in actions), output
            assert b"\x1b[3J" not in output, "visible refresh must not erase terminal scrollback"
        while True:
            ready, _, _ = select.select([master], [], [], 0)
            if not ready:
                break
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            output.extend(chunk)
        return output.decode("utf-8", "replace")
    finally:
        if proc.poll() is None:
            proc.terminate(); proc.wait(timeout=5)
        os.close(master)


def approve(decision, identity="both", selection="all"):
    return approve_actions([(decision, selection)], identity)


def run_cli(*args, identity="both", decision="y", env=None, expected_code=0,
            expected_stdout=None, expected_stderr=None):
    uid, gid, groups = USERS[identity]
    env_args = [item for key, value in (env or {}).items() for item in ("--env", f"{key}={value}")]
    proc = subprocess.Popen(
        ["docker", "exec", *env_args, NAME, *setpriv_args(uid, gid, groups),
         "/usr/bin/mayi", *map(str, args)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    prefix = wait_text(proc, proc.stderr, b"MAYI_REQUEST_PENDING")
    display = approve(decision, "both")
    stdout, stderr = proc.communicate(timeout=320)
    stderr = prefix + stderr
    if proc.returncode != expected_code:
        raise AssertionError(f"{args!r}: exit {proc.returncode}, expected {expected_code}; stderr={stderr!r}")
    if expected_stdout is not None and stdout != expected_stdout:
        raise AssertionError(f"{args!r}: stdout {stdout!r}, expected {expected_stdout!r}")
    if expected_stderr is not None and expected_stderr not in stderr:
        raise AssertionError(f"{args!r}: missing stderr {expected_stderr!r} in {stderr!r}")
    return stdout, stderr, display


def queue_command(executable, argv=(), after=(), identity="both"):
    uid, gid, groups = USERS[identity]
    args = ["/usr/bin/mayi", "--queue"]
    for request_id in after:
        args += ["--after", request_id]
    args += [executable, *argv]
    started = time.monotonic()
    result = docker_as(uid, gid, groups, *args, timeout=15, check=False)
    elapsed = time.monotonic() - started
    if result.returncode != 0:
        raise RuntimeError(f"queue submission failed: rc={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}")
    value = result.stdout.decode("ascii", "strict")
    assert len(value) == 36 and value.startswith("rq_") and value.endswith("\n") and all(c in "0123456789abcdef" for c in value[3:-1]), value
    assert result.stderr == b"", result.stderr
    assert elapsed < 10, f"queue submission did not return immediately: {elapsed}s"
    return value.strip()


def wait_jobs(request_ids, fail=0, fail_instant=False, timeout=60, identity="both"):
    uid, gid, groups = USERS[identity]
    args = ["/usr/bin/mayi", "--wait", f"--fail={fail}"]
    if fail_instant:
        args.append("--fail-instant")
    args += list(request_ids)
    return docker_as(uid, gid, groups, *args, timeout=timeout, check=False)


def status_job(request_id):
    uid, gid, groups = USERS["both"]
    return docker_as(uid, gid, groups, "/usr/bin/mayi", "--status", request_id, check=False)


def execution_request_ids():
    if SYSTEMD_MODE:
        logs = docker("journalctl", "-u", "mayi-privileged-executor.service", "-o", "cat", "--no-pager").stdout
    else:
        logs = docker("sh", "-c", "cat /tmp/executor.log").stdout
    return [line.split(b"request_id=", 1)[1].split()[0].decode() for line in logs.splitlines() if line.startswith(b"event=EXECUTION_STARTED ")]


def approval_console_probe(identity="both", password=APPROVER_PASSWORD, env=None, extra_args=()):
    uid, gid, groups = USERS[identity]
    master, slave = pty.openpty()
    env_args = [item for key, value in (env or {}).items() for item in ("--env", f"{key}={value}")]
    proc = subprocess.Popen(
        ["docker", "exec", "-it", *env_args, NAME,
         *setpriv_args(uid, gid, groups, no_new_privs=False), "/usr/bin/mayi-approve", *extra_args],
        stdin=slave, stdout=slave, stderr=slave, close_fds=True,
    )
    os.close(slave)
    output = bytearray()
    sent = 0
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline and proc.poll() is None:
            prompts = output.count(b"Password:")
            while password is not None and sent < prompts:
                os.write(master, password.encode() + b"\n")
                sent += 1
            if b"Waiting for Mayi requests..." in output or b"[a] allow all" in output:
                os.write(master, b"q\n")
                proc.wait(timeout=5)
                break
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    output.extend(os.read(master, 4096))
                except OSError:
                    break
            if password is None and b"Password:" in output:
                # Cancel through the PAM conversation so the child restores
                # terminal state and exits instead of orphaning docker exec.
                os.write(master, b"\x03\n")
                proc.wait(timeout=5)
                break
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)
        return proc.returncode, output.decode("utf-8", "replace")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        os.close(master)


def console_rejection(identity, injected_group):
    uid, gid, _ = USERS[identity]
    master, slave = pty.openpty()
    proc = subprocess.Popen(
        ["docker", "exec", "-it", NAME, *setpriv_args(uid, gid, (injected_group,)), "/usr/bin/mayi-approve"],
        stdin=slave, stdout=slave, stderr=slave, close_fds=True,
    )
    os.close(slave)
    output = bytearray()
    deadline = time.monotonic() + 10
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    output.extend(os.read(master, 4096))
                except OSError:
                    break
            if proc.poll() is not None:
                break
        if proc.poll() is None:
            proc.kill()
            proc.wait()
            raise RuntimeError("unauthorized approval console did not exit")
        return proc.returncode, output.decode("utf-8", "replace")
    finally:
        os.close(master)


def python_as(identity, source, *args, groups=None, check=True):
    uid, gid, default_groups = USERS[identity] if isinstance(identity, str) and identity in USERS else tuple(map(int, identity.split(":"))) + ((),)
    groups = default_groups if groups is None else groups
    result = docker_as(uid, gid, groups, "python3", "-c", source, *args, input=None, timeout=30, check=False)
    if check and result.returncode:
        raise RuntimeError(f"container Python failed: {result.stderr.decode(errors='replace')}")
    return result


def propose(executable, argv, identity="both"):
    source = '''import json,sys
from mayi.executor import RustExecutorClient
from mayi.operations import Operation,Kind
r=RustExecutorClient(socket_path="/run/mayi/request/broker.sock",expected_broker_uid=23002).submit([Operation(Kind.EXEC,sys.argv[1],tuple(json.loads(sys.argv[2])))])
print(json.dumps(r))'''
    return json.loads(python_as(identity, source, executable, json.dumps(argv)).stdout)


def count_call(instance, challenge, digest, extra="", identity="both", groups=None):
    source = '''import json,sys
from mayi.executor import RustExecutorClient
c=RustExecutorClient(socket_path="/run/mayi/request/broker.sock",expected_broker_uid=23002)
try:
 r=c.consume_approved(*sys.argv[1:4]); print(json.dumps({"ok":True,"execution":r.get("execution"),"stdout_hex":r.get("stdout_hex")}))
except Exception as e: print(json.dumps({"ok":False,"error":str(e)}))'''
    return json.loads(python_as(identity, source, instance, challenge, digest, extra, groups=groups).stdout)


def direct_consume(instance, challenge, digest, extra_key, extra_value, identity="both"):
    source = '''import json,sys
from mayi.executor import _exchange
p={"type":"CONSUME_APPROVED","protocol":5,"broker_instance_id":sys.argv[1],"challenge_id":sys.argv[2],"request_digest":sys.argv[3]}
p[sys.argv[4]]=json.loads(sys.argv[5]); print(json.dumps(_exchange("/run/mayi/request/broker.sock",p,5,23002)))'''
    return json.loads(python_as(identity, source, instance, challenge, digest, extra_key, json.dumps(extra_value)).stdout)


def list_and_view(identity, proposal):
    source = '''import json,sys
from mayi.executor import RustApprovalAuthorityClient
c=RustApprovalAuthorityClient("/run/mayi/approval/broker.sock",expected_broker_uid=23002)
r=c.list_pending(); v=c.get_challenge(r["broker_instance_id"],sys.argv[1],sys.argv[2]); print(json.dumps({"pending":r["pending"],"view_id":v["view_id"]}))'''
    return json.loads(python_as(identity, source, proposal["challenge_id"], proposal["request_digest"]).stdout)


def unauthorized_cli(identity, injected_group):
    uid, gid, _ = USERS[identity]
    result = docker_as(uid, gid, (injected_group,), "/usr/bin/mayi", "/usr/bin/id", check=False)
    return result.returncode, result.stderr.decode("utf-8", "replace")


def raw_executor(identity, request_id, executable=None, argv=None, groups=None):
    source = '''import json,socket,struct,sys
m={"type":"EXEC_REQUEST","protocol":1,"request_id":sys.argv[1],"executable":sys.argv[2],"argv":json.loads(sys.argv[3])}
s=socket.socket(socket.AF_UNIX);s.settimeout(3)
try:
 s.connect("/run/mayi/executor/executor.sock"); b=json.dumps(m,separators=(",",":")).encode(); s.sendall(struct.pack(">I",len(b))+b)
 h=s.recv(4)
 if len(h)<4: print(json.dumps({"closed":True})); sys.exit(0)
 n=struct.unpack(">I",h)[0]; d=b""
 while len(d)<n:d+=s.recv(n-len(d))
 print(d.decode())
except (OSError,TimeoutError) as e: print(json.dumps({"closed":True,"error":str(e)}))'''
    return python_as(identity, source, request_id, executable or command_path("true"), json.dumps(argv or ["true"]), groups=groups, check=False)


def start_services():
    if SYSTEMD_MODE:
        docker("systemctl", "start", "mayi-privileged-executor.service", "mayi-broker.service")
        assert docker("systemctl", "is-active", "mayi-privileged-executor.service", "mayi-broker.service").returncode == 0
        return
    docker("sh", "-eu", "-c", 'setpriv --no-new-privs --reuid=0 --regid=23012 --clear-groups /usr/libexec/mayi/privileged-executor >/tmp/executor.log 2>&1 & echo $! >/tmp/executor.pid; i=0; while [ ! -S /run/mayi/executor/executor.sock ]; do i=$((i+1)); [ "$i" -lt 100 ]; sleep .1; done; setpriv --no-new-privs --reuid=23002 --regid=23012 --groups=23011,23013 /usr/bin/mayi-executor --request-socket /run/mayi/request/broker.sock --request-gid 23011 --approval-socket /run/mayi/approval/broker.sock --approval-gid 23013 >/tmp/broker.log 2>&1 & echo $! >/tmp/broker.pid; i=0; while [ ! -S /run/mayi/request/broker.sock ] || [ ! -S /run/mayi/approval/broker.sock ]; do i=$((i+1)); [ "$i" -lt 100 ]; sleep .1; done')


def stop_services():
    if SYSTEMD_MODE:
        docker("systemctl", "stop", "mayi-broker.service", "mayi-privileged-executor.service")
        return
    docker("sh", "-eu", "-c", 'kill $(cat /tmp/broker.pid) 2>/dev/null || true; kill $(cat /tmp/executor.pid) 2>/dev/null || true; sleep .3; rm -f /run/mayi/request/broker.sock /run/mayi/approval/broker.sock /run/mayi/executor/executor.sock /run/mayi/executor/executor.lock')


def create_human_roles():
    docker("sh", "-eu", "-c", '''
for spec in "1000:1000:mayi-both" "1001:1001:mayi-requester-only" "1002:1002:mayi-approver-only" "1003:1003:mayi-unrelated"; do
  uid=${spec%%:*}; rest=${spec#*:}; gid=${rest%%:*}; name=${rest#*:}
  groupadd -g "$gid" "$name"
  useradd -u "$uid" -g "$gid" -M -s /usr/sbin/nologin "$name"
done
useradd -u 1004 -g mayi-requester -M -s /usr/sbin/nologin mayi-primary-requester-user
useradd -u 1005 -g mayi-approver -M -s /usr/sbin/nologin mayi-primary-approver-user
usermod -aG mayi-requester,mayi-approver mayi-both
usermod -aG mayi-requester mayi-requester-only
usermod -aG mayi-approver mayi-approver-only
''')
    docker("usermod", "-aG", "mayi-requester", "mayi-primary-requester-user")
    docker("usermod", "-aG", "mayi-approver", "mayi-primary-approver-user")
    if TARGET_VERSION in {"0.4.0", "0.4.1", "0.4.1-1"}:
        accounts = ("mayi-both", "mayi-approver-only", "mayi-primary-approver-user")
        docker("chpasswd", input="".join(f"{account}:{APPROVER_PASSWORD}\n" for account in accounts).encode())
        docker("chpasswd", input=f"mayi-unrelated:{WRONG_PASSWORD}\n".encode())


def check_roles_and_topology():
    docker("sh", "-eu", "-c", '''
grep -q -- '--request-gid 23011' /usr/lib/systemd/system/mayi-broker.service
grep -q -- '--approval-gid 23013' /usr/lib/systemd/system/mayi-broker.service
! grep -q -- '--request-uid' /usr/lib/systemd/system/mayi-broker.service
! grep -q -- '--approval-uid' /usr/lib/systemd/system/mayi-broker.service
test "$(id -u mayi-broker)" = 23002
test "$(id -g mayi-broker)" = 23012
test "$(getent group mayi-requester | cut -d: -f3)" = 23011
test "$(getent group mayi-approver | cut -d: -f3)" = 23013
test "$(getent group mayi-broker-socket | cut -d: -f3)" = 23012
test "$(stat -c %u:%g:%a /run/mayi/request)" = 23002:23011:750
test "$(stat -c %u:%g:%a /run/mayi/approval)" = 23002:23013:750
test "$(stat -c %u:%g:%a /run/mayi/executor)" = 0:23012:750
''')
    names = {"both": "mayi-both", "requester": "mayi-requester-only", "approver": "mayi-approver-only", "unauthorized": "mayi-unrelated"}
    for identity, expected in (("both", {23011, 23013}), ("requester", {23011}), ("approver", {23013}), ("unauthorized", set())):
        gids = {int(x) for x in docker("id", "-G", names[identity]).stdout.split()}
        # docker id resolves the NSS account's supplemental list.
        assert expected.issubset(gids), (identity, gids, expected)


def broker_restart():
    if SYSTEMD_MODE:
        docker("systemctl", "restart", "mayi-broker.service")
        assert docker("systemctl", "is-active", "mayi-broker.service").returncode == 0
        return
    docker("sh", "-c", "kill $(cat /tmp/broker.pid); sleep .3; rm -f /run/mayi/request/broker.sock /run/mayi/approval/broker.sock")
    docker("sh", "-c", 'setpriv --no-new-privs --reuid=23002 --regid=23012 --groups=23011,23013 /usr/bin/mayi-executor --request-socket /run/mayi/request/broker.sock --request-gid 23011 --approval-socket /run/mayi/approval/broker.sock --approval-gid 23013 >/tmp/broker.log 2>&1 & echo $! >/tmp/broker.pid')
    for _ in range(100):
        if docker("test", "-S", "/run/mayi/request/broker.sock", check=False).returncode == 0:
            return
        time.sleep(.1)
    raise RuntimeError("broker restart did not restore its socket")


def package_path(version):
    root = "/root" if SYSTEMD_MODE else "/tmp"
    return f"{root}/mayi_{version}_amd64.deb"


def install_package(version):
    path = package_path(version)
    if APT_MODE:
        docker("apt-get", "install", "-y", path, timeout=120)
        return
    if SYSTEMD_MODE:
        docker("dpkg", "-i", path, timeout=120)
        return
    docker("apt-get", "install", "-y", path, timeout=120)


def manpage_qualification():
    expected = {
        "mayi": "/usr/share/man/man1/mayi.1.gz",
        "mayi-workflow": "/usr/share/man/man7/mayi-workflow.7.gz",
    }
    for name, path in expected.items():
        docker("test", "-f", path)
        located = docker("man", "-w", name).stdout.decode().strip().splitlines()
        assert path in located, (name, located, path)
    for args, required in (
        (("man", "mayi"), ("NAME", "SYNOPSIS", "SEE ALSO", "mayi-workflow")),
        (("man", "1", "mayi"), ("NAME", "SYNOPSIS")),
        (("man", "mayi-workflow"), ("NAME", "REQUESTER WORKFLOW", "APPROVER WORKFLOW")),
        (("man", "7", "mayi-workflow"), ("NAME", "REQUESTER WORKFLOW", "RESULTS AND LIMITS")),
    ):
        rendered = docker("env", "MANPAGER=cat", *args).stdout.decode(errors="replace")
        for section in required:
            assert section in rendered, (args, section, rendered[:1000])
    print("INSTALLED MAN MAYI(1)/MAYI-WORKFLOW(7), DEFAULT LOOKUP: PASS")


def install_for_mode():
    if MODE in {"upgrade", "upgrade020", "upgrade021", "upgrade022", "upgrade030", "upgrade031", "upgrade032", "upgrade040", "upgrade041"}:
        baseline = {"upgrade021": "0.2.1", "upgrade022": "0.2.2", "upgrade030": "0.3.0", "upgrade031": "0.3.1", "upgrade032": "0.3.2", "upgrade040": "0.4.0", "upgrade041": "0.4.1"}.get(MODE, "0.2.0")
        install_package(baseline)
        create_human_roles()
        requester_groups = docker("id", "-G", "mayi-both").stdout
        approver_groups = docker("id", "-G", "mayi-approver-only").stdout
        legacy_accounts = {}
        for user in ("mayi-requester", "mayi-approver"):
            result = docker("getent", "passwd", user, check=False)
            if result.returncode == 0:
                legacy_accounts[user] = result.stdout.split(b":")[2]
        if SYSTEMD_MODE:
            ready_before = journal_events(b"event=EXECUTOR_READY ")
            socket_before = docker("stat", "-c", "%d:%i", "/run/mayi/executor/executor.sock").stdout.strip()
        upgraded = docker("dpkg", "-i", package_path(TARGET_VERSION), timeout=120) if SYSTEMD_MODE else docker("apt-get", "install", "-y", package_path(TARGET_VERSION), timeout=120)
        output = upgraded.stdout + upgraded.stderr
        assert b"addgroup with two arguments" not in output, output
        assert docker("id", "-G", "mayi-both").stdout == requester_groups
        assert docker("id", "-G", "mayi-approver-only").stdout == approver_groups
        for user in ("mayi-requester", "mayi-approver"):
            result = docker("getent", "passwd", user, check=False)
            if user in legacy_accounts:
                assert result.returncode == 0 and result.stdout.split(b":")[2] == legacy_accounts[user], (user, result.stdout)
            else:
                assert result.returncode != 0, ("unexpected legacy account created", user, result.stdout)
        if SYSTEMD_MODE:
            assert docker("test", "-S", "/run/mayi/executor/executor.sock", check=False).returncode == 0
            assert docker("stat", "-c", "%d:%i", "/run/mayi/executor/executor.sock").stdout.strip() != socket_before, "upgrade did not replace the old executor socket"
            assert journal_events(b"event=EXECUTOR_READY ") > ready_before, "systemd did not restart executor after upgrade"
            assert docker("systemctl", "is-active", "mayi-privileged-executor.service", "mayi-broker.service").returncode == 0
        print(f"UPGRADE {baseline} -> {TARGET_VERSION}; MEMBERSHIPS AND LEGACY ACCOUNTS PRESERVED: PASS")
    else:
        install_package(TARGET_VERSION)
        if TARGET_VERSION in {"0.2.1", "0.2.2", "0.3.0", "0.3.1", "0.3.2", "0.4.0", "0.4.1", "0.4.1-1"}:
            assert docker("getent", "passwd", "mayi-requester", check=False).returncode != 0
            assert docker("getent", "passwd", "mayi-approver", check=False).returncode != 0
        create_human_roles()
        method = "APT" if APT_MODE else "dpkg"
        print(f"FRESH INSTALL {TARGET_VERSION} VIA {method}: PASS")
    if TARGET_VERSION in {"0.3.2", "0.4.0", "0.4.1", "0.4.1-1"}:
        manpage_qualification()
    if TARGET_VERSION == "0.4.1-1":
        version = docker("dpkg-query", "-W", "-f=${Version}", "mayi").stdout.decode().strip()
        maintainer = docker("dpkg-deb", "-f", package_path(TARGET_VERSION), "Maintainer").stdout.decode().strip()
        copyright = docker("cat", "/usr/share/doc/mayi/copyright").stdout.decode()
        assert version == TARGET_VERSION, version
        assert maintainer == "Eugen Lupricht <mayi@lupricht.net>", maintainer
        assert "License: MIT" in copyright and "Copyright: 2026 Eugen Lupricht" in copyright
        print("PACKAGE VERSION/MAINTAINER/MIT COPYRIGHT METADATA: PASS")


def queue_qualification():
    before = execution_request_ids()
    d1 = queue_command(command_path("true"))
    d2 = queue_command("/usr/bin/id", after=[d1])
    d3 = queue_command(command_path("true"), after=[d2])
    assert len(set((d1, d2, d3))) == 3
    assert execution_request_ids() == before, "queue submission executed before approval"
    wrong = docker_as(*USERS["requester"], "/usr/bin/mayi", "--queue", "--after", d1, command_path("true"), check=False)
    assert wrong.returncode != 0 and wrong.stdout == b"" and b"DEPENDENCY_OWNER_MISMATCH" in wrong.stderr
    unknown = docker_as(*USERS["both"], "/usr/bin/mayi", "--queue", "--after", "rq_" + "0" * 32, command_path("true"), check=False)
    assert unknown.returncode != 0 and unknown.stdout == b""
    display = approve("a")
    assert "Commands: 3" in display and f"[0] {command_path('true')}" in display and "[1] /usr/bin/id" in display
    waited = wait_jobs([d1, d2, d3])
    assert waited.returncode == 0, (waited.stdout, waited.stderr)
    for request_id in (d1, d2, d3):
        assert request_id.encode() in waited.stdout and b"SUCCEEDED" in waited.stdout
    assert execution_request_ids()[len(before):] == [d1[3:], d2[3:], d3[3:]]
    assert b"SUCCEEDED" in status_job(d3).stdout
    print("QUEUE CLI/UNIQUE IDS/ALL-SUCCESS ASYNCHRONOUS CHAIN/WAIT/STATUS: PASS")

    before = execution_request_ids()
    left = queue_command(command_path("true"))
    right = queue_command(command_path("true"))
    child = queue_command(command_path("true"), after=[left, right])
    branch_display = approve("a")
    assert "Commands: 3" in branch_display and ("after: 0,1" in branch_display or "after: 1,0" in branch_display)
    assert wait_jobs([left, right, child]).returncode == 0
    branch_events = execution_request_ids()[len(before):]
    assert set(branch_events[:2]) == {left[3:], right[3:]} and branch_events[2] == child[3:]
    print("MULTIPLE DEPENDENCIES / BRANCHING DAG EXECUTES AFTER ALL PARENTS: PASS")

    before = execution_request_ids()
    d1 = queue_command(command_path("false"))
    d2 = queue_command("/usr/bin/id", after=[d1])
    d3 = queue_command(command_path("true"), after=[d2])
    approve("a")
    waited = wait_jobs([d1, d2, d3])
    assert waited.returncode == 1 and b"FAILED mayi=14 child=1" in waited.stdout
    assert f"{d2} BLOCKED mayi=14 child=- dependency={d1}".encode() in waited.stdout
    assert f"{d3} BLOCKED mayi=14 child=- dependency={d2}".encode() in waited.stdout
    assert execution_request_ids()[len(before):] == [d1[3:]]
    print("FAILED DEPENDENCY BLOCKS TRANSITIVE COMMANDS: PASS")

    before = execution_request_ids()
    d1 = queue_command(command_path("true"))
    d2 = queue_command("/usr/bin/id", after=[d1])
    d3 = queue_command(command_path("true"), after=[d2])
    approve("d", selection="0")
    approve("a")
    waited = wait_jobs([d1, d2, d3])
    assert waited.returncode == 1 and b"DENIED mayi=10" in waited.stdout
    assert f"{d2} BLOCKED mayi=14 child=- dependency={d1}".encode() in waited.stdout
    assert f"{d3} BLOCKED mayi=14 child=- dependency={d2}".encode() in waited.stdout
    assert execution_request_ids() == before
    print("DENIED DEPENDENCY BLOCKS TRANSITIVE COMMANDS: PASS")

    before = execution_request_ids()
    d1 = queue_command(command_path("true"))
    d2 = queue_command("/usr/bin/id", after=[d1])
    d3 = queue_command(command_path("true"), after=[d2])
    approve("02")
    assert b"PENDING_APPROVAL" in status_job(d2).stdout
    assert b"WAITING_DEPENDENCY" in status_job(d3).stdout
    approve("1")
    waited = wait_jobs([d1, d2, d3])
    assert waited.returncode == 0
    assert execution_request_ids()[len(before):] == [d1[3:], d2[3:], d3[3:]]
    print("PARTIAL APPROVAL / APPROVED CHILD WAITS / DEPENDENCY ORDER: PASS")

    before = execution_request_ids()
    d1 = queue_command(command_path("true"))
    d2 = queue_command(command_path("true"), after=[d1])
    d3 = queue_command(command_path("true"), after=[d2])
    approve("210")
    waited = wait_jobs([d1, d2, d3])
    assert waited.returncode == 0 and execution_request_ids()[len(before):] == [d1[3:], d2[3:], d3[3:]]
    print("NUMERIC APPROVAL SET IGNORES INPUT ORDER: PASS")

    before = execution_request_ids()
    first = queue_command(command_path("true"))
    second = queue_command(command_path("true"))
    skipped_display = approve_actions([("s", None), ("a", None)])
    displayed_ids = [request_id for request_id in (first, second) if skipped_display.count(request_id) >= 2]
    assert displayed_ids, "skipped set did not resurface after cycling"
    approve("a")
    assert wait_jobs([first, second]).returncode == 0
    assert len(execution_request_ids()) == len(before) + 2
    print("SKIP NAVIGATION DOES NOT MUTATE AUTHORITY AND SKIPPED SET RESURFACES: PASS")

    before = execution_request_ids()
    d1 = queue_command(command_path("true"))
    d2 = queue_command("/usr/bin/id", after=[d1])
    approve("f", selection="0")
    approve("a")
    waited = wait_jobs([d1, d2])
    assert waited.returncode == 1 and b"EXPLAIN_REQUESTED mayi=20" in waited.stdout
    assert f"{d2} BLOCKED mayi=14 child=- dependency={d1}".encode() in waited.stdout
    assert execution_request_ids() == before
    print("FOLLOW-UP EXECUTES NOTHING AND BLOCKS DEPENDENTS: PASS")

    good = queue_command(command_path("true"))
    bad = queue_command(command_path("false"))
    approve("a")
    approve("a")
    assert wait_jobs([good, bad], fail=0).returncode == 1
    assert wait_jobs([good, bad], fail=1).returncode == 0
    print("WAIT FAILURE BUDGET --fail=0/1: PASS")

    failed = queue_command(command_path("false"))
    approve("a")
    assert wait_jobs([failed], fail=1).returncode == 0
    slow = queue_command(command_path("sleep"), ["8"])
    approve("a")
    started = time.monotonic()
    early = wait_jobs([failed, slow], fail=0, fail_instant=True)
    elapsed = time.monotonic() - started
    assert early.returncode == 1 and elapsed < 8, (early.returncode, elapsed, early.stdout)
    assert b"RUNNING" in early.stdout or b"NOT_OBSERVED" in early.stdout
    assert wait_jobs([failed, slow], fail=1, timeout=15).returncode == 0
    print("FAIL-INSTANT RETURNS WITHOUT CANCELLING OTHER JOB: PASS")


def authentication_qualification():
    docker("test", "-f", "/etc/pam.d/mayi-approve")
    pam_config = docker("cat", "/etc/pam.d/mayi-approve").stdout
    assert b"@include common-auth" in pam_config and b"@include common-account" in pam_config

    launcher = docker_as(*USERS["both"], "/usr/bin/mayi-approve", "--password", check=False)
    assert launcher.returncode != 0 and b"options are accepted" in launcher.stderr and b"Password:" not in launcher.stderr

    piped = docker(
        "setpriv", "--no-new-privs", "--reuid=1000", "--regid=1000", "--groups=23011,23013",
        "/usr/bin/mayi-approve", check=False, input=(APPROVER_PASSWORD + "\n").encode(),
    )
    assert piped.returncode != 0 and b"interactive terminal" in piped.stderr
    assert b"Password:" not in piped.stdout + piped.stderr

    if SYSTEMD_MODE:
        docker("systemctl", "stop", "mayi-broker.service")
    else:
        docker("sh", "-c", "kill $(cat /tmp/broker.pid); sleep .3; rm -f /run/mayi/request/broker.sock /run/mayi/approval/broker.sock")
    code, output = approval_console_probe(password=WRONG_PASSWORD)
    assert code != 0 and "Password:" in output and "Authenticated." not in output, output
    assert "APPROVAL_AUTH_SUCCESS" not in output
    assert "Waiting for Mayi requests" not in output and WRONG_PASSWORD not in output
    broker_restart()

    pending = queue_command(command_path("true"), identity="requester")
    code, output = approval_console_probe(password=WRONG_PASSWORD)
    assert code != 0 and "Authenticated." not in output and "Waiting for Mayi requests" not in output, output
    assert "Commands:" not in output and pending not in output and WRONG_PASSWORD not in output
    code, output = approval_console_probe(password=WRONG_PASSWORD, env={"PAM_USER": "mayi-unrelated"})
    assert code != 0 and "Authenticated." not in output and "Waiting for Mayi requests" not in output, output

    docker("chage", "-E", "1", "mayi-both")
    try:
        code, output = approval_console_probe(password=APPROVER_PASSWORD)
    finally:
        docker("chage", "-E", "-1", "mayi-both")
    assert code != 0 and "Authenticated." not in output and "Waiting for Mayi requests" not in output, output
    assert pending not in output and "Commands:" not in output

    code, output = approval_console_probe(password=None, env={"MAYI_PASSWORD": APPROVER_PASSWORD})
    assert "Password:" in output and "Authenticated." not in output and "Waiting for Mayi requests" not in output, output
    assert APPROVER_PASSWORD not in output

    docker("mv", "/etc/pam.d/mayi-approve", "/tmp/mayi-approve.pam.saved")
    try:
        code, output = approval_console_probe()
    finally:
        docker("mv", "/tmp/mayi-approve.pam.saved", "/etc/pam.d/mayi-approve")
    assert code != 0 and "Authenticated." not in output and "Waiting for Mayi requests" not in output, output
    assert pending not in output and "Commands:" not in output

    display = approve("a", identity="approver")
    assert "requester UID: 1001" in display
    assert wait_jobs([pending], identity="requester").returncode == 0

    first_id = queue_command(command_path("true"), identity="both")
    before = execution_request_ids()
    later_ids = []
    def submit_new_request_after_first_decision(index):
        if index == 0:
            later_ids.append(queue_command(command_path("true"), identity="both"))
    display = approve_actions([("a", "all"), ("d", "all")], identity="both", on_decision=submit_new_request_after_first_decision)
    assert display.count("Password:") == 1 and "Authenticated." not in display, display
    assert "APPROVAL_AUTH_SUCCESS" not in display
    assert display.count("\x1b[2J\x1b[H") == 2 and "\x1b[3J" not in display, display
    first_clear = display.index("\x1b[2J\x1b[H")
    first_ack = display.index("Approved:")
    second_request = display.index("Commands:", first_ack)
    second_clear = display.index("\x1b[2J\x1b[H", first_clear + 1)
    deny_ack = display.index("Denied:", second_request)
    assert first_clear < first_ack < second_request < second_clear < deny_ack, display
    assert len(later_ids) == 1
    assert set(execution_request_ids()[len(before):]) == {first_id[3:]}
    assert wait_jobs([first_id]).returncode == 0
    denied_result = wait_jobs(later_ids)
    assert denied_result.returncode == 1 and b"DENIED" in denied_result.stdout, denied_result

    separate = queue_command(command_path("true"), identity="requester")
    display = approve("a", identity="approver")
    assert "requester UID: 1001" in display and "Authenticated." not in display
    assert "APPROVAL_AUTH_SUCCESS" not in display
    assert wait_jobs([separate], identity="requester").returncode == 0
    if SYSTEMD_MODE:
        auth_log = docker("journalctl", "-u", "mayi-broker.service", "-o", "cat", "--no-pager").stdout
    else:
        auth_log = docker("cat", "/tmp/broker.log").stdout
    assert APPROVER_PASSWORD.encode() not in auth_log and WRONG_PASSWORD.encode() not in auth_log
    print("PAM TTY AUTH, NO PREAUTH BROKER ACCESS, SAME/SEPARATE ACCOUNTS, PROCESS-LOCAL SESSION: PASS")


def run():
    install_for_mode()
    start_services()
    check_roles_and_topology()

    # Role membership, including root-controlled NSS supplementary lookup.
    before = count_started()
    code, error = unauthorized_cli("unauthorized", 23011)
    assert code == 13 and "UNAUTHORIZED_REQUESTER" in error, (code, error)
    code, error = unauthorized_cli("approver", 23011)
    assert code == 13 and "UNAUTHORIZED_REQUESTER" in error, (code, error)
    code, error = console_rejection("unauthorized", 23013)
    assert code != 0 and "MAYI_UNAUTHORIZED_APPROVER" in error, (code, error)
    code, error = console_rejection("requester", 23013)
    assert code != 0 and "MAYI_UNAUTHORIZED_APPROVER" in error, (code, error)
    assert count_started() == before
    print("REQUESTER/APPROVER GROUP AUTHORIZATION AND CLEAR ERRORS: PASS")
    if TARGET_VERSION in {"0.4.0", "0.4.1", "0.4.1-1"}:
        authentication_qualification()

    # Supplementary requester A and approver B; other members cannot consume A's request.
    before = count_started()
    p = propose("/usr/bin/printf", ["printf", "A"], "requester")
    first_view = list_and_view("both", p)
    second_view = list_and_view("approver", p)
    assert first_view["pending"] and second_view["pending"]
    text = approve("y", "approver")
    assert "requester UID: 1001" in text and "Executor: UID 0 / GID 23012" in text
    if SYSTEMD_MODE:
        log = docker("journalctl", "-u", "mayi-broker.service", "-o", "cat", "--no-pager").stdout
    else:
        log = docker("sh", "-c", "grep 'event=VIEW_APPROVED' /tmp/broker.log").stdout
    assert b"requester_uid=1001" in log and b"approver_uid=1002" in log
    other = count_call(p["broker_instance_id"], p["challenge_id"], p["request_digest"], identity="both")
    assert not other["ok"] and "UNAUTHORIZED_REQUESTER" in other["error"]
    assert count_started() == before
    result = count_call(p["broker_instance_id"], p["challenge_id"], p["request_digest"], identity="requester")
    assert result["ok"] and bytes.fromhex(result["stdout_hex"]) == b"A"
    assert count_started() == before + 1
    print("ACTUAL REQUESTER/APPROVER UID BINDING AND CROSS-CONSUME DENIAL: PASS")

    # Primary-GID role memberships (not just supplementary memberships).
    before = count_started()
    proc = subprocess.Popen(["docker", "exec", NAME, *setpriv_args(1004, 23011, ()), "/usr/bin/mayi", command_path("true")], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    wait_text(proc, proc.stderr, b"MAYI_REQUEST_PENDING")
    primary_approval = approve("y", "primary_approver")
    out, err = proc.communicate(timeout=320)
    assert proc.returncode == 0 and count_started() == before + 1, (out, err)
    assert "requester UID: 1004" in primary_approval
    print("PRIMARY-GROUP REQUESTER/APPROVER: PASS")

    # Same UID may hold both human roles.
    before = count_started()
    stdout, _, display = run_cli("/usr/bin/id")
    assert b"uid=0(root)" in stdout and "/usr/bin/id" in display and "[argv0=/usr/bin/id]" in display
    assert count_started() == before + 1
    print("SAME USER BOTH ROLES / APPROVE: PASS")

    before = count_started()
    _, stderr, _ = run_cli(command_path("true"), decision="n", expected_code=10, expected_stderr=b"MAYI_APPROVAL_DENIED")
    assert b"MAYI_APPROVAL_DENIED" in stderr and count_started() == before
    print("DENY: PASS")

    before = count_started()
    _, stderr, _ = run_cli(command_path("true"), decision="e", expected_code=20, expected_stderr=b"MAYI_EXPLAIN_REQUESTED")
    assert b"MAYI_EXPLAIN_REQUESTED" in stderr and count_started() == before
    print("EXPLAIN: PASS")

    before = count_started()
    _, stderr, _ = run_cli(command_path("false"), expected_code=14, expected_stderr=b"MAYI_EXECUTION_FAILED")
    assert count_started() == before + 1
    print("EXECUTION FAILURE: PASS")

    before = count_started()
    literal = b"; touch /tmp/pwned"
    stdout, _, display = run_cli("/usr/bin/printf", "%s", literal.decode(), expected_stdout=literal)
    assert 'touch /tmp/pwned' in display
    assert docker("test", "!", "-e", "/tmp/pwned", check=False).returncode == 0
    assert count_started() == before + 1
    print("LITERAL METACHARACTERS: PASS")

    before = count_started()
    # Do not set LD_PRELOAD in the requester process: the dynamic loader may
    # refuse to start the client before Mayi can submit the proposal.
    env = {"PATH": "/tmp", "LD_LIBRARY_PATH": "/tmp", "MAYI_UNTRUSTED": "injected"}
    stdout, _, _ = run_cli("/usr/bin/env", env=env)
    assert b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" in stdout
    assert b"LD_PRELOAD" not in stdout and b"LD_LIBRARY_PATH" not in stdout and b"MAYI_UNTRUSTED" not in stdout
    assert count_started() == before + 1
    print("CONTROLLED ENVIRONMENT: PASS")

    before = count_started()
    p = propose("/usr/bin/printf", ["printf", "A"])
    approve("y")
    for key, value in (("argv", ["printf", "B"]), ("executable", command_path("false"))):
        response = direct_consume(p["broker_instance_id"], p["challenge_id"], p["request_digest"], key, value)
        assert response.get("ok") is False and response.get("code") == "UNKNOWN_FIELD", response
    result = count_call(p["broker_instance_id"], p["challenge_id"], p["request_digest"])
    assert result["ok"] and bytes.fromhex(result["stdout_hex"]) == b"A"
    duplicate = count_call(p["broker_instance_id"], p["challenge_id"], p["request_digest"])
    assert not duplicate["ok"] and "ALREADY_CONSUMED" in duplicate["error"]
    assert count_started() == before + 1
    print("IMMUTABLE EXECUTABLE/ARGV AND DOUBLE CONSUME: PASS")

    before = count_started()
    p = propose(command_path("true"), ["true"], "requester")
    approve("y", "approver")
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: count_call(p["broker_instance_id"], p["challenge_id"], p["request_digest"], identity="requester"), range(12)))
    assert sum(1 for item in results if item.get("ok") and item.get("execution") == "SUCCEEDED") == 1
    assert count_started() == before + 1
    print("CONCURRENT CONSUME: PASS")

    before = count_started()
    for identity, groups in (("requester", (23011,)), ("approver", (23013,))):
        attack = raw_executor(identity, "d" * 32, groups=groups)
        assert attack.returncode != 0 or json.loads(attack.stdout).get("closed")
    attack = raw_executor("unauthorized", "e" * 32, groups=(23012,))
    assert b"closed" in attack.stdout or attack.returncode != 0
    assert count_started() == before
    print("DIRECT EXECUTOR ACCESS AND EXACT BROKER UID: PASS")

    before = count_started()
    p = propose(command_path("true"), ["true"])
    approve("y")
    broker_restart()
    stale = count_call(p["broker_instance_id"], p["challenge_id"], p["request_digest"])
    assert not stale["ok"] and "BROKER_INSTANCE_MISMATCH" in stale["error"]
    assert count_started() == before
    print("BROKER RESTART INVALIDATION: PASS")

    before = count_started()
    request_id = "f" * 32
    payload = {"type": "EXEC_REQUEST", "protocol": 1, "request_id": request_id, "executable": command_path("true"), "argv": ["true"]}
    encoded = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    client_code = '''import base64,json,socket,struct,sys
s=socket.socket(socket.AF_UNIX);s.settimeout(5);s.connect("/run/mayi/executor/executor.sock");b=base64.b64decode(sys.argv[1]);s.sendall(struct.pack(">I",len(b))+b);n=struct.unpack(">I",s.recv(4))[0];d=b""
while len(d)<n:d+=s.recv(n-len(d))
print(d.decode())'''
    direct = python_as("23002:23012", client_code, encoded, groups=(23011, 23013))
    assert json.loads(direct.stdout)["status"] == "EXECUTED"
    repeated = python_as("23002:23012", client_code, encoded, groups=(23011, 23013))
    assert json.loads(repeated.stdout)["status"] == "EXECUTION_UNKNOWN"
    assert count_started() == before + 1
    print("EXECUTOR REQUEST DEDUPLICATION: PASS")

    queue_qualification()

    if SYSTEMD_MODE and KEEP_PACKAGE:
        print("SYSTEMD PACKAGE RETAINED FOR LIFECYCLE QUALIFICATION: PASS")
        return
    stop_services()
    docker("dpkg", "--purge", "mayi")
    docker("sh", "-eu", "-c", '''
test ! -e /usr/bin/mayi
test ! -e /var/lib/mayi-privileged-executor
getent passwd mayi-both >/dev/null
getent passwd mayi-requester-only >/dev/null
getent passwd mayi-approver-only >/dev/null
getent group mayi-requester | grep -q mayi-requester-only
getent group mayi-approver | grep -q mayi-approver-only
! getent passwd mayi-broker
''')
    print("PACKAGE PURGE PRESERVES HUMAN USERS/MEMBERSHIPS: PASS")


if __name__ == "__main__":
    run()
