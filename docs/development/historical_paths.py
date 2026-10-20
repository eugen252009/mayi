"""Explicitly redacted archive views; original evidence remains in Git history.

Only maintainer checkout/release paths and historical temporary evidence paths
are removed. All other bytes, including results, hashes and failures, are kept.
This is presentation redaction, not requalification or runnable archive examples.
"""
import re

LOCAL_PATH = re.compile(
    r'(?:/home/eugen/projekte/|~/projekte/|/tmp/mayi-(?:release|qemu-qualification)[^\s/]*[/]|/tmp/tpahub/)'
    r'[^\s`*;,)]*'
)
NOTICE = (
    '> Archive view: maintainer-local paths have been omitted. Commands containing\n'
    '> `[local-only path omitted]` are historical records, not runnable instructions.\n'
    '> Original bytes remain at the commit/path recorded by the documentation checker.\n\n'
)

def archive_view(body):
    text = body.decode('utf-8')
    redacted, count = LOCAL_PATH.subn('[local-only path omitted]', text)
    return (NOTICE + redacted).encode('utf-8') if count else body
