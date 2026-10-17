"""Guard against reintroducing cross-test flock inheritance races.

Filesystem tests create subprocesses and must isolate whole test lifetimes, not
individual fixtures. This checks harness structure, not filesystem safety.
"""
from pathlib import Path
import re


def test_every_filesystem_unit_test_acquires_isolation_first():
    source = (Path(__file__).resolve().parents[1] / "executor/src/filesystem.rs").read_text()
    tests = source.split("#[cfg(test)]\nmod tests {", 1)[1]
    functions = re.findall(r"#\[test\]\s+fn\s+(\w+)\s*\(\)\s*\{([^\n]*\n[^\n]*)", tests)
    assert functions, "filesystem tests were not found"
    for name, start in functions:
        assert start.strip() == "let _isolation = isolate_test();", name
