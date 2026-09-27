import os

EXECUTOR = "/usr/bin/mayi-executor"
BROKER_UID = "23002"
SOCKET = "/run/mayi/approval/broker.sock"


def main():
    os.execv(EXECUTOR, [EXECUTOR, "--approval-console", "--approval-socket", SOCKET, "--broker-uid", BROKER_UID])
