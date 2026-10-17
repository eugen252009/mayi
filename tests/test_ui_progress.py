import io
import os
import pty
import termios
import pytest
from mayi.progress import Waiting


class Stream(io.StringIO):
    def isatty(self):
        return True


@pytest.mark.parametrize('outcome', ['complete', 'denied', 'timeout', 'disconnect', 'cancel'])
def test_spinner_stops_on_every_exit(monkeypatch, outcome):
    monkeypatch.setenv('TERM', 'xterm')
    stream = Stream()
    now = [0.0]
    with Waiting(stream, lambda: now[0]) as progress:
        progress.tick()
        first = stream.getvalue()
        progress.tick()
        assert stream.getvalue() == first
        now[0] = .5
        progress.tick()
        assert stream.getvalue() != first
    final = stream.getvalue()
    progress.tick()
    assert stream.getvalue() == final
    assert final.endswith('\r\x1b[2K')


def test_redirect_and_dumb_have_no_output(monkeypatch):
    for stream, term in [(io.StringIO(), 'xterm'), (Stream(), 'dumb')]:
        monkeypatch.setenv('TERM', term)
        with Waiting(stream) as progress:
            progress.tick()
        assert stream.getvalue() == ''


def test_pty_does_not_change_terminal_modes(monkeypatch):
    monkeypatch.setenv('TERM', 'xterm')
    master, slave = pty.openpty()
    try:
        before = termios.tcgetattr(slave)
        with os.fdopen(os.dup(slave), 'w') as stream:
            with Waiting(stream) as progress:
                progress.tick()
        assert termios.tcgetattr(slave) == before
        assert b'Waiting for human approval' in os.read(master, 4096)
    finally:
        os.close(master)
        os.close(slave)


def test_updates_are_rate_limited(monkeypatch):
    monkeypatch.setenv('TERM', 'xterm')
    stream = Stream()
    with Waiting(stream, lambda: 1.0) as progress:
        for _ in range(10000):
            progress.tick()
    assert stream.getvalue().count('Waiting') == 1
