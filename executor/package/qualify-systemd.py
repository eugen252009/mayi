#!/usr/bin/env python3
"""Real systemd package/authentication/socket qualification in Debian 10–13 containers."""
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
PACKAGE_DIR = ROOT / "executor/target/debian"
SUITE = os.environ.get("MAYI_DEBIAN_SUITE", "trixie")
IMAGE = f"mayi-systemd-qualification:{SUITE}"
SYSTEMD_IMAGE = ROOT / "executor/package/systemd-qualification"
SCRIPT = ROOT / "executor/package/qualify-mvp.py"
PACKAGES = {
    "0.2.0": PACKAGE_DIR / "mayi_0.2.0_amd64.deb",
    "0.2.1": PACKAGE_DIR / "mayi_0.2.1_amd64.deb",
    "0.2.2": PACKAGE_DIR / "mayi_0.2.2_amd64.deb",
    "0.3.0": PACKAGE_DIR / "mayi_0.3.0_amd64.deb",
    "0.3.1": PACKAGE_DIR / "mayi_0.3.1_amd64.deb",
    "0.3.2": PACKAGE_DIR / "mayi_0.3.2_amd64.deb",
    "0.4.0": PACKAGE_DIR / "mayi_0.4.0_amd64.deb",
}
UNIT_EXECUTOR = "mayi-privileged-executor.service"
UNIT_BROKER = "mayi-broker.service"
SOCKET = "/run/mayi/executor/executor.sock"


def run(args, *, check=True, timeout=60, capture=True):
    result = subprocess.run(
        list(map(str, args)), text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        timeout=timeout,
    )
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {args!r}\n{result.stdout}\n{result.stderr}")
    return result


def dexec(name, *args, check=True, timeout=40):
    return run(["docker", "exec", name, *args], check=check, timeout=timeout)


def wait_systemd(name):
    for _ in range(120):
        state = dexec(name, "systemctl", "is-system-running", check=False, timeout=5)
        if state.stdout.strip() in {"running", "degraded", "maintenance"}:
            return
        time.sleep(0.25)
    raise RuntimeError(f"systemd did not become available in {name}")


def start_container(name):
    run([
        "docker", "run", "-d", "--name", name, "--privileged",
        "--cgroupns=private", "--network=none", "--tmpfs", "/run",
        "--tmpfs", "/run/lock", "--tmpfs", "/tmp", IMAGE,
    ])
    topology = run([
        "docker", "inspect", "--format",
        "{{.HostConfig.Privileged}}|{{len .Mounts}}|{{.HostConfig.CgroupnsMode}}|{{.HostConfig.NetworkMode}}",
        name,
    ]).stdout.strip()
    if topology != "true|0|private|none":
        raise RuntimeError(f"unexpected systemd qualification topology: {topology}")
    wait_systemd(name)
    for version, package in PACKAGES.items():
        run(["docker", "cp", package, f"{name}:/root/{package.name}"])


def container_shell(name, script, *, check=True, timeout=60):
    return dexec(name, "sh", "-eu", "-c", script, check=check, timeout=timeout)


def unit_status(name, unit):
    return dexec(name, "systemctl", "is-active", unit, check=False).stdout.strip()


def assert_active(name, unit):
    if unit_status(name, unit) != "active":
        status = dexec(name, "systemctl", "status", "--no-pager", unit, check=False).stdout
        raise AssertionError(f"{unit} is not active:\n{status}")


def daemon_count(name, executable):
    source = '''import os
path=sys.argv[1]
count=0
for item in os.listdir("/proc"):
 if item.isdigit():
  try:
   if os.readlink("/proc/"+item+"/exe") == path: count += 1
  except (OSError, PermissionError): pass
print(count)'''
    result = dexec(name, "python3", "-c", "import sys\n" + source, executable)
    return int(result.stdout.strip())


def assert_topology(name):
    expected = {
        "/run/mayi/request": "mayi-broker:mayi-requester:750",
        "/run/mayi/approval": "mayi-broker:mayi-approver:750",
        "/run/mayi/executor": "root:mayi-broker-socket:750",
        SOCKET: "root:mayi-broker-socket:660",
    }
    for path, value in expected.items():
        actual = dexec(name, "stat", "-c", "%U:%G:%a", path).stdout.strip()
        if actual != value:
            raise AssertionError(f"wrong owner/group/mode for {path}: {actual}, expected {value}")
    if daemon_count(name, "/usr/libexec/mayi/privileged-executor") != 1:
        raise AssertionError("executor process count is not exactly one")
    if daemon_count(name, "/usr/bin/mayi-executor") != 1:
        raise AssertionError("broker process count is not exactly one")
    execstart = dexec(name, "systemctl", "show", UNIT_BROKER, "-p", "ExecStart", "--value").stdout
    if "--request-uid" in execstart or "--approval-uid" in execstart:
        raise AssertionError(f"stale broker unit is loaded: {execstart}")
    if "--request-gid 23011" not in execstart or "--approval-gid 23013" not in execstart:
        raise AssertionError(f"incorrect broker unit is loaded: {execstart}")
    service_type = dexec(name, "systemctl", "show", UNIT_EXECUTOR, "-p", "Type", "--value").stdout.strip()
    if service_type != "notify":
        raise AssertionError(f"executor is not readiness-gated (Type={service_type})")
    for unit in (UNIT_EXECUTOR, UNIT_BROKER):
        assert_active(name, unit)


def journal_count(name, unit, prefix):
    result = dexec(name, "journalctl", "-u", unit, "-o", "cat", "--no-pager")
    return sum(line.startswith(prefix) for line in result.stdout.splitlines())


def clean_stop_start(name):
    for _ in range(3):
        dexec(name, "systemctl", "stop", UNIT_EXECUTOR)
        if dexec(name, "test", "!", "-e", SOCKET, check=False).returncode:
            raise AssertionError("clean executor stop left its socket path")
        dexec(name, "systemctl", "start", UNIT_EXECUTOR)
        assert_active(name, UNIT_EXECUTOR)
        dexec(name, "systemctl", "start", UNIT_BROKER)
        assert_topology(name)
    print("SYSTEMD CLEAN STOP/START ×3: PASS")


def assert_broker_sockets(name):
    for path, expected in (
        ("/run/mayi/request/broker.sock", "mayi-broker:mayi-requester:660"),
        ("/run/mayi/approval/broker.sock", "mayi-broker:mayi-approver:660"),
    ):
        actual = dexec(name, "stat", "-c", "%U:%G:%a", path).stdout.strip()
        if actual != expected:
            raise AssertionError(f"bad broker socket metadata at {path}: {actual}")


def wait_broker_socket(name, path):
    for _ in range(100):
        if dexec(name, "test", "-S", path, check=False).returncode == 0:
            return
        time.sleep(0.05)
    raise AssertionError(f"broker socket not ready: {path}")


def start_broker(name):
    dexec(name, "systemctl", "reset-failed", UNIT_BROKER, check=False)
    dexec(name, "systemctl", "start", UNIT_BROKER, timeout=30)
    wait_broker_socket(name, "/run/mayi/request/broker.sock")
    wait_broker_socket(name, "/run/mayi/approval/broker.sock")
    assert_active(name, UNIT_BROKER)
    assert_broker_sockets(name)


def stop_broker(name):
    dexec(name, "systemctl", "stop", UNIT_BROKER, check=False)
    for path in ("/run/mayi/request/broker.sock", "/run/mayi/approval/broker.sock"):
        if dexec(name, "test", "-e", path, check=False).returncode == 0:
            raise AssertionError(f"graceful broker stop left {path}")


def expect_broker_start_rejection(name, path, label):
    result = dexec(name, "systemctl", "start", UNIT_BROKER, check=False, timeout=30)
    time.sleep(0.25)
    if unit_status(name, UNIT_BROKER) == "active":
        raise AssertionError(f"broker started despite {label} at {path}; systemctl={result.stdout} {result.stderr}")
    dexec(name, "systemctl", "stop", UNIT_BROKER, check=False)
    dexec(name, "systemctl", "reset-failed", UNIT_BROKER, check=False)


def broker_socket_lifecycle(name):
    request = "/run/mayi/request/broker.sock"
    approval = "/run/mayi/approval/broker.sock"
    stale_code = '''import os,socket,sys
p=sys.argv[1]; gid=int(sys.argv[2]); s=socket.socket(socket.AF_UNIX); s.bind(p); os.chown(p,23002,gid); os.chmod(p,0o660); s.close()'''

    # Normal SIGTERM stop closes and unlinks both broker listener paths.
    stop_broker(name)
    start_broker(name)
    print("BROKER CLEAN STOP/START: PASS")

    # Independently leave a real stale socket on each endpoint.
    for path, gid, label in ((request, 23011, "request"), (approval, 23013, "approval")):
        stop_broker(name)
        dexec(name, "python3", "-c", stale_code, path, str(gid))
        stale_id = dexec(name, "stat", "-c", "%d:%i", path).stdout.strip()
        start_broker(name)
        current_id = dexec(name, "stat", "-c", "%d:%i", path).stdout.strip()
        if current_id == stale_id:
            raise AssertionError(f"stale broker {label} socket was not rebound")
    print("BROKER STALE REQUEST AND APPROVAL SOCKETS: PASS")

    # SIGKILL bypasses cleanup; systemd restarts the broker and startup recovery
    # replaces both old listener pathnames.
    before = {
        request: dexec(name, "stat", "-c", "%d:%i", request).stdout.strip(),
        approval: dexec(name, "stat", "-c", "%d:%i", approval).stdout.strip(),
    }
    dexec(name, "systemctl", "kill", "--kill-who=main", "--signal=SIGKILL", UNIT_BROKER)
    for path in (request, approval):
        if dexec(name, "test", "-S", path, check=False).returncode:
            raise AssertionError(f"broker SIGKILL did not leave {path}")
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if unit_status(name, UNIT_BROKER) == "active" and daemon_count(name, "/usr/bin/mayi-executor") == 1:
            break
        time.sleep(0.1)
    else:
        raise AssertionError("broker did not recover after SIGKILL")
    for path in (request, approval):
        if dexec(name, "stat", "-c", "%d:%i", path).stdout.strip() == before[path]:
            raise AssertionError(f"broker reused crash-left pathname without rebind: {path}")
    assert_broker_sockets(name)
    print("BROKER SIGKILL STALE-SOCKET RECOVERY: PASS")

    # Non-socket entries at either endpoint fail closed and remain untouched.
    for path, label in ((approval, "symlink"), (request, "regular file"), (approval, "directory")):
        stop_broker(name)
        if label == "symlink":
            target = "/root/mayi-broker-target"
            dexec(name, "sh", "-c", f"printf untouched > {target}; ln -s {target} {path}")
            before_id = dexec(name, "stat", "-c", "%d:%i", target).stdout.strip()
        elif label == "regular file":
            dexec(name, "sh", "-c", f"printf regular-untouched > {path}")
            before_id = dexec(name, "stat", "-c", "%d:%i", path).stdout.strip()
        else:
            dexec(name, "mkdir", path)
            before_id = dexec(name, "stat", "-c", "%d:%i", path).stdout.strip()
        expect_broker_start_rejection(name, path, label)
        if label == "symlink":
            if dexec(name, "readlink", path).stdout.strip() != target or dexec(name, "cat", target).stdout != "untouched":
                raise AssertionError("broker symlink target was modified")
            dexec(name, "rm", path)
        elif label == "regular file":
            if dexec(name, "stat", "-c", "%d:%i", path).stdout.strip() != before_id or dexec(name, "cat", path).stdout != "regular-untouched":
                raise AssertionError("broker regular file was modified")
            dexec(name, "rm", path)
        else:
            if dexec(name, "stat", "-c", "%d:%i", path).stdout.strip() != before_id:
                raise AssertionError("broker directory was removed/replaced")
            dexec(name, "rmdir", path)
        start_broker(name)
    print("BROKER SYMLINK/FILE/DIRECTORY REPLACEMENTS: PASS")

    # A foreign live listener on each broker endpoint must remain bound.
    foreign_code = '''import os,socket,sys
p=sys.argv[1]; gid=int(sys.argv[2]); pidfile=sys.argv[3]; s=socket.socket(socket.AF_UNIX); s.bind(p); os.chown(p,23002,gid); os.chmod(p,0o660); s.listen(8); open(pidfile,"w").write(str(os.getpid()))
while True:
 c,_=s.accept(); c.close()'''
    for path, gid, label in ((request, 23011, "request"), (approval, 23013, "approval")):
        stop_broker(name)
        pidfile = f"/root/foreign-broker-{label}.pid"
        run(["docker", "exec", "-d", name, "python3", "-c", foreign_code, path, str(gid), pidfile])
        for _ in range(50):
            if dexec(name, "test", "-S", path, check=False).returncode == 0:
                break
            time.sleep(0.05)
        foreign_id = dexec(name, "stat", "-c", "%d:%i", path).stdout.strip()
        expect_broker_start_rejection(name, path, f"foreign live {label} socket")
        if dexec(name, "stat", "-c", "%d:%i", path).stdout.strip() != foreign_id:
            raise AssertionError(f"live foreign broker {label} socket was removed")
        pid = dexec(name, "cat", pidfile).stdout.strip()
        dexec(name, "kill", "-TERM", pid, check=False)
        time.sleep(0.15)
        dexec(name, "rm", "-f", path)
        start_broker(name)
    print("BROKER FOREIGN LIVE REQUEST/APPROVAL SOCKETS: PASS")


def restart_stress(name):
    # Negative-object tests deliberately triggered start failures; clear their
    # systemd rate-limit counter before measuring healthy repeated restarts.
    dexec(name, "systemctl", "reset-failed", UNIT_EXECUTOR, UNIT_BROKER)
    assert_active(name, UNIT_EXECUTOR)
    assert_active(name, UNIT_BROKER)
    for index in range(100):
        dexec(name, "systemctl", "restart", UNIT_EXECUTOR, timeout=40)
        assert_active(name, UNIT_EXECUTOR)
        if daemon_count(name, "/usr/libexec/mayi/privileged-executor") != 1:
            raise AssertionError(f"executor duplicate/missing after restart {index + 1}")
    print("SYSTEMD EXECUTOR RESTARTS: 100/100 PASS")
    for index in range(100):
        dexec(name, "systemctl", "restart", UNIT_BROKER, timeout=40)
        assert_active(name, UNIT_BROKER)
        if daemon_count(name, "/usr/bin/mayi-executor") != 1:
            raise AssertionError(f"broker duplicate/missing after restart {index + 1}")
    print("SYSTEMD BROKER RESTARTS: 100/100 PASS")


def expect_unit_start_failure(name, label):
    result = dexec(name, "systemctl", "start", UNIT_EXECUTOR, check=False, timeout=40)
    if result.returncode == 0:
        raise AssertionError(f"executor unexpectedly started with {label}")
    dexec(name, "systemctl", "stop", UNIT_EXECUTOR, check=False, timeout=20)
    dexec(name, "systemctl", "reset-failed", UNIT_EXECUTOR, check=False)


def test_socket_attack_matrix(name):
    dexec(name, "systemctl", "stop", UNIT_EXECUTOR)
    if dexec(name, "test", "!", "-e", SOCKET, check=False).returncode:
        raise AssertionError("graceful stop did not unlink executor socket")
    dexec(name, "systemctl", "start", UNIT_EXECUTOR)
    assert_active(name, UNIT_EXECUTOR)
    print("ABSENT SOCKET / CLEAN START: PASS")

    # A stale pathname from a real bound-then-closed listener is reclaimable.
    stale_code = '''import os,socket,sys
p=sys.argv[1]; s=socket.socket(socket.AF_UNIX); s.bind(p); os.chown(p,0,23012); os.chmod(p,0o660); s.close()'''
    dexec(name, "systemctl", "stop", UNIT_EXECUTOR)
    dexec(name, "python3", "-c", stale_code, SOCKET)
    stale_identity = dexec(name, "stat", "-c", "%d:%i", SOCKET).stdout.strip()
    dexec(name, "systemctl", "start", UNIT_EXECUTOR)
    assert_active(name, UNIT_EXECUTOR)
    current_identity = dexec(name, "stat", "-c", "%d:%i", SOCKET).stdout.strip()
    if current_identity == stale_identity:
        raise AssertionError("stale socket inode was not replaced")
    print("REAL STALE UNIX SOCKET RECOVERY: PASS")

    dexec(name, "systemctl", "stop", UNIT_EXECUTOR)
    # Unexpected ownership is ambiguous and must remain in place.
    dexec(name, "python3", "-c", stale_code.replace("23012", "0"), SOCKET)
    unexpected_identity = dexec(name, "stat", "-c", "%d:%i", SOCKET).stdout.strip()
    expect_unit_start_failure(name, "wrong-owned stale socket")
    if dexec(name, "stat", "-c", "%d:%i", SOCKET).stdout.strip() != unexpected_identity:
        raise AssertionError("wrong-owned stale socket was removed")
    dexec(name, "rm", "-f", SOCKET)
    dexec(name, "systemctl", "start", UNIT_EXECUTOR)
    assert_active(name, UNIT_EXECUTOR)
    print("UNEXPECTED SOCKET OWNERSHIP: FAIL-CLOSED PASS")

    # Symlink target and non-socket replacements are never removed.
    target = "/root/mayi-socket-target"
    dexec(name, "systemctl", "stop", UNIT_EXECUTOR)
    dexec(name, "sh", "-c", f"printf untouched > {target}; ln -s {target} {SOCKET}")
    expect_unit_start_failure(name, "symlink")
    if dexec(name, "readlink", SOCKET).stdout.strip() != target or dexec(name, "cat", target).stdout != "untouched":
        raise AssertionError("symlink or its target was modified")
    dexec(name, "rm", SOCKET)
    dexec(name, "systemctl", "start", UNIT_EXECUTOR)
    assert_active(name, UNIT_EXECUTOR)
    print("SYMLINK TARGET PRESERVED: PASS")

    dexec(name, "systemctl", "stop", UNIT_EXECUTOR)
    dexec(name, "sh", "-c", f"printf regular-untouched > {SOCKET}")
    expect_unit_start_failure(name, "regular file")
    if dexec(name, "cat", SOCKET).stdout != "regular-untouched":
        raise AssertionError("regular file was modified")
    dexec(name, "rm", SOCKET)
    dexec(name, "systemctl", "start", UNIT_EXECUTOR)
    assert_active(name, UNIT_EXECUTOR)
    print("REGULAR FILE PRESERVED: PASS")

    dexec(name, "systemctl", "stop", UNIT_EXECUTOR)
    dexec(name, "mkdir", SOCKET)
    expect_unit_start_failure(name, "directory")
    if dexec(name, "test", "-d", SOCKET, check=False).returncode:
        raise AssertionError("directory replacement was removed")
    dexec(name, "rmdir", SOCKET)
    dexec(name, "systemctl", "start", UNIT_EXECUTOR)
    assert_active(name, UNIT_EXECUTOR)
    print("DIRECTORY PRESERVED: PASS")

    # Requires+After and Type=notify must prevent a healthy broker without a
    # ready executor.
    dexec(name, "systemctl", "stop", UNIT_BROKER, UNIT_EXECUTOR)
    dexec(name, "sh", "-c", f"printf sentinel > {SOCKET}")
    broker_start = dexec(name, "systemctl", "start", UNIT_BROKER, check=False, timeout=40)
    if broker_start.returncode == 0 or unit_status(name, UNIT_BROKER) == "active":
        raise AssertionError("broker became healthy while executor startup failed")
    if dexec(name, "cat", SOCKET).stdout != "sentinel":
        raise AssertionError("executor dependency failure modified socket-path object")
    dexec(name, "rm", SOCKET)
    dexec(name, "systemctl", "reset-failed", UNIT_EXECUTOR, UNIT_BROKER)
    dexec(name, "systemctl", "start", UNIT_BROKER)
    assert_topology(name)
    print("BROKER REQUIRES A READY EXECUTOR: PASS")

    # Foreign but correctly owned/mode live listener: connection proves live.
    foreign_code = '''import os,socket,sys,time
p=sys.argv[1]; s=socket.socket(socket.AF_UNIX); s.bind(p); os.chown(p,0,23012); os.chmod(p,0o660); s.listen(8); open("/root/foreign.pid","w").write(str(os.getpid()))
while True:
 c,_=s.accept(); c.close()'''
    dexec(name, "systemctl", "stop", UNIT_EXECUTOR)
    run(["docker", "exec", "-d", name, "python3", "-c", foreign_code, SOCKET])
    for _ in range(50):
        if dexec(name, "test", "-S", SOCKET, check=False).returncode == 0:
            break
        time.sleep(0.1)
    if dexec(name, "test", "-S", SOCKET, check=False).returncode:
        raise AssertionError("foreign listener did not bind")
    foreign_identity = dexec(name, "stat", "-c", "%d:%i", SOCKET).stdout.strip()
    expect_unit_start_failure(name, "foreign live socket")
    if dexec(name, "stat", "-c", "%d:%i", SOCKET).stdout.strip() != foreign_identity:
        raise AssertionError("live foreign socket was unlinked")
    foreign_pid = dexec(name, "cat", "/root/foreign.pid").stdout.strip()
    dexec(name, "kill", "-TERM", foreign_pid, check=False)
    time.sleep(0.2)
    dexec(name, "rm", "-f", SOCKET)
    dexec(name, "systemctl", "start", UNIT_EXECUTOR)
    assert_active(name, UNIT_EXECUTOR)
    print("FOREIGN LIVE SOCKET PRESERVED: PASS")

    # A SIGKILL leaves the actual pathname; systemd's next start reclaims it.
    dexec(name, "systemctl", "stop", UNIT_EXECUTOR)
    direct = 'setpriv --no-new-privs --reuid=0 --regid=23012 --clear-groups /usr/libexec/mayi/privileged-executor >/root/crash-executor.log 2>&1 & echo $! >/root/crash-executor.pid'
    dexec(name, "sh", "-c", direct)
    for _ in range(100):
        if "event=EXECUTOR_READY" in dexec(name, "cat", "/root/crash-executor.log").stdout:
            break
        time.sleep(0.05)
    pid = dexec(name, "cat", "/root/crash-executor.pid").stdout.strip()
    dexec(name, "kill", "-KILL", pid)
    time.sleep(0.1)
    if dexec(name, "test", "-S", SOCKET, check=False).returncode:
        raise AssertionError("SIGKILL did not leave the expected stale socket")
    dexec(name, "systemctl", "start", UNIT_EXECUTOR)
    assert_active(name, UNIT_EXECUTOR)
    dexec(name, "systemctl", "start", UNIT_BROKER)
    print("SIGKILL STALE SOCKET → SYSTEMD RESTART: PASS")
    assert_topology(name)


def competing_start(name):
    dexec(name, "systemctl", "stop", UNIT_EXECUTOR)
    command = '''setpriv --no-new-privs --reuid=0 --regid=23012 --clear-groups /usr/libexec/mayi/privileged-executor'''
    container_shell(name, f"{command} >/root/race-a.log 2>&1 & echo $! >/root/race-a.pid; {command} >/root/race-b.log 2>&1 & echo $! >/root/race-b.pid")
    for _ in range(100):
        ready = sum("event=EXECUTOR_READY" in dexec(name, "cat", f"/root/race-{letter}.log").stdout for letter in "ab")
        if ready:
            break
        time.sleep(0.05)
    time.sleep(0.2)
    ready = sum("event=EXECUTOR_READY" in dexec(name, "cat", f"/root/race-{letter}.log").stdout for letter in "ab")
    if ready != 1 or daemon_count(name, "/usr/libexec/mayi/privileged-executor") != 1:
        raise AssertionError(f"competing start authority count invalid (ready={ready})")
    winner = next(letter for letter in "ab" if "event=EXECUTOR_READY" in dexec(name, "cat", f"/root/race-{letter}.log").stdout)
    pid = dexec(name, "cat", f"/root/race-{winner}.pid").stdout.strip()
    dexec(name, "kill", "-TERM", pid)
    for _ in range(100):
        if dexec(name, "test", "!", "-e", SOCKET, check=False).returncode == 0:
            break
        time.sleep(0.05)
    if dexec(name, "test", "-e", SOCKET, check=False).returncode == 0:
        raise AssertionError("winning competing executor did not clean up")
    dexec(name, "systemctl", "start", UNIT_EXECUTOR)
    assert_active(name, UNIT_EXECUTOR)
    print("SIMULTANEOUS EXECUTOR STARTS: ONE WINNER / ONE AUTHORITY PASS")


def restart_qualification(name):
    assert_topology(name)
    clean_stop_start(name)
    competing_start(name)
    test_socket_attack_matrix(name)
    broker_socket_lifecycle(name)
    restart_stress(name)
    print("SYSTEMD LIFECYCLE QUALIFICATION: PASS")


def install_failure_gate(name):
    # Wrong pre-existing group GID simulates a mandatory package-account setup failure.
    dexec(name, "groupadd", "-g", "23010", "mayi-requester")
    result = dexec(name, "dpkg", "-i", f"/root/{PACKAGES['0.4.0'].name}", check=False, timeout=120)
    if result.returncode == 0:
        raise AssertionError("mandatory account setup conflict incorrectly configured package")
    status = dexec(name, "dpkg-query", "-W", "-f=${db:Status-Status}", "mayi", check=False)
    if status.stdout.strip() not in {"half-configured", "unpacked"}:
        raise AssertionError(f"dpkg status did not show failed configuration: {status.stdout!r}")
    output = result.stdout + result.stderr
    if "fatal: addgroup with two arguments" in output:
        raise AssertionError("invalid addgroup syntax remains")
    print("MANDATORY PACKAGE SETUP FAILURE → DPKG CONFIGURATION FAILS: PASS")


def pam_conffile_lifecycle(name):
    config = "/etc/pam.d/mayi-approve"
    package = f"/root/{PACKAGES['0.4.0'].name}"
    original = dexec(name, "cat", config).stdout
    if "@include common-auth" not in original or "@include common-account" not in original:
        raise AssertionError(f"unexpected installed PAM policy: {original!r}")
    dexec(name, "dpkg", "--remove", "mayi", timeout=120)
    if dexec(name, "cat", config).stdout != original:
        raise AssertionError("dpkg remove did not preserve the PAM conffile")
    dexec(name, "dpkg", "-i", package, timeout=120)
    if dexec(name, "cat", config).stdout != original:
        raise AssertionError("reinstall replaced the preserved PAM conffile")
    marker = "# local qualification customization\n"
    dexec(name, "sh", "-c", "printf '\\n# local qualification customization\\n' >> /etc/pam.d/mayi-approve")
    dexec(name, "dpkg", "--force-confold", "-i", package, timeout=120)
    if marker not in dexec(name, "cat", config).stdout:
        raise AssertionError("package reinstall overwrote a locally modified PAM conffile")
    dexec(name, "dpkg", "--purge", "mayi", timeout=120)
    if dexec(name, "test", "!", "-e", config, check=False).returncode != 0:
        raise AssertionError("dpkg purge did not remove the PAM conffile")
    print("PAM CONFFILE REMOVE/REINSTALL/PRESERVE/PURGE: PASS")


def qualify_environment(name, mode):
    start_container(name)
    env = os.environ.copy()
    env.update({
        "MAYI_TEST_CONTAINER": name,
        "MAYI_TEST_MODE": mode,
        "MAYI_TARGET_VERSION": "0.4.0",
        "MAYI_TEST_SYSTEMD": "1",
        "MAYI_TEST_APT": "1" if SUITE == "bookworm" and mode == "fresh" else "0",
        "MAYI_TEST_KEEP_PACKAGE": "1",
    })
    # Pass qualification mode into the installed-package flow without exposing
    # it to the host environment.
    run([
        "env",
        *[f"{key}={env[key]}" for key in (
            "MAYI_TEST_CONTAINER", "MAYI_TEST_MODE", "MAYI_TARGET_VERSION",
            "MAYI_TEST_SYSTEMD", "MAYI_TEST_APT", "MAYI_TEST_KEEP_PACKAGE",
        )],
        sys.executable, SCRIPT,
    ], timeout=900, capture=False)
    restart_qualification(name)
    pam_conffile_lifecycle(name)
    dexec(name, "systemctl", "stop", UNIT_BROKER, UNIT_EXECUTOR, check=False)
    dexec(name, "dpkg", "--purge", "mayi", check=False, timeout=120)
    run(["docker", "rm", "-f", name], check=False)


def main():
    for version, package in PACKAGES.items():
        if not package.is_file():
            raise SystemExit(f"required retained package missing: {package}")
    expected_020 = "685632ff860e1efe1a55adf7af99b3d82446755875936d3aa8bf5e978635ef9d"
    expected_021 = "1799e555c6e983b99b10e3c92d52b46079b2b9fa853618c424c317ebc12316dd"
    expected_022 = "24b5d51daf274290af2ee73df3393be70ce588567a0608cd7a571ec4f9f35f58"
    expected_030 = "0f356c880d8351f9ca5a05267530b8b9741a08b6b715ee0c9d1fe571ac851e57"
    expected_031 = "9162530d3052389f5b84edef2680e379350bbd79a0981e247628d08a1df1b57e"
    expected_032 = "f5e81423e198cb386584de5a5060d429733b9205499ca73f5a76a512729159b1"
    expected_040 = "d0a28d1e0e46837f395bc687b93f76742a91056a33358a5201b5a6ca28946f86"
    for version, expected in (("0.2.0", expected_020), ("0.2.1", expected_021), ("0.2.2", expected_022), ("0.3.0", expected_030), ("0.3.1", expected_031), ("0.3.2", expected_032), ("0.4.0", expected_040)):
        actual = subprocess.check_output(["sha256sum", str(PACKAGES[version])], text=True).split()[0]
        if actual != expected:
            raise SystemExit(f"{version} package hash mismatch: {actual}")
    run(["docker", "build", "--build-arg", f"DEBIAN_SUITE={SUITE}", "-t", IMAGE, SYSTEMD_IMAGE], timeout=900, capture=False)
    if SUITE == "trixie":
        modes = ("fresh", "upgrade020", "upgrade021", "upgrade022", "upgrade030", "upgrade031", "upgrade032")
    else:
        modes = ("fresh", "upgrade031", "upgrade032")
    suffixes = (*modes, "failure")
    names = [f"mayi-systemd-{SUITE}-{os.getpid()}-{suffix}" for suffix in suffixes]
    passed = False
    try:
        for name, mode in zip(names[:-1], modes):
            qualify_environment(name, mode)
        start_container(names[-1])
        install_failure_gate(names[-1])
        passed = True
    finally:
        if passed:
            run(["docker", "rm", "-f", *names], check=False)
        else:
            for name in names:
                status = run(["docker", "exec", name, "systemctl", "status", "--no-pager", UNIT_EXECUTOR], check=False, timeout=15)
                logs = run(["docker", "exec", name, "journalctl", "-u", UNIT_EXECUTOR, "-n", "80", "--no-pager"], check=False, timeout=15)
                if status.stdout:
                    print(status.stdout, file=sys.stderr)
                if logs.stdout:
                    print(logs.stdout, file=sys.stderr)
            print("FAILED qualification containers retained for diagnosis:", *names, file=sys.stderr)
    print(f"{SUITE}: FRESH + {', '.join(modes[1:])} + PAM/MANPAGES/QUEUE/SYSTEMD LIFECYCLE QUALIFICATION: PASS")


if __name__ == "__main__":
    main()
