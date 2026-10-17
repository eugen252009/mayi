"""Human-only, timer-driven progress. No network, threads or authorization state."""
import os
import sys
import time


class Waiting:
    def __init__(self, stream=None, clock=time.monotonic):
        self.stream = stream if stream is not None else sys.stderr
        self.clock = clock
        self.started = clock()
        self.last = None
        self.active = False
        term = os.environ.get("TERM", "")
        self.enabled = self.stream.isatty() and any(
            term == prefix or term.startswith(prefix + "-")
            for prefix in ("xterm", "screen", "tmux", "linux", "vt100", "ansi")
        )

    def __enter__(self):
        return self

    def tick(self):
        elapsed = max(0, self.clock() - self.started)
        frame = int(elapsed * 4)
        if not self.enabled or frame == self.last:
            return
        self.last = frame
        self.active = True
        self.stream.write("\r\x1b[2K{} Waiting for human approval; elapsed {:02d}:{:02d} (not a health check)".format(
            "|/-\\"[frame % 4], int(elapsed) // 60, int(elapsed) % 60))
        self.stream.flush()

    def __exit__(self, *_):
        self.stop()

    def stop(self):
        if self.active:
            self.stream.write("\r\x1b[2K")
            self.stream.flush()
        self.active = False
        self.enabled = False
