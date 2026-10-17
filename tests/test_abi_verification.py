from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "executor/package/verify_abi.py"
SPEC = spec_from_file_location("mayi_verify_abi", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ABI = module_from_spec(SPEC)
SPEC.loader.exec_module(ABI)


def test_version_order_is_numeric():
    assert ABI.version_tuple("2.9") < ABI.version_tuple("2.31")
    assert ABI.version_tuple("3.4.9") < ABI.version_tuple("3.4.28")


def test_dependency_parser_handles_versions_and_alternatives():
    control = "Depends: libc6 (>= 2.31), libpam0g | libpam0g-alt, libgcc-s1\n"
    assert ABI.parse_dependency_names(control) == {"libc6", "libpam0g", "libgcc-s1"}


def test_deliberately_incompatible_versioned_elf_is_rejected(tmp_path):
    if not all(shutil.which(tool) for tool in ("cc", "ld", "readelf", "objdump")):
        pytest.skip("native ELF fixture tools are unavailable")
    (tmp_path / "newer.c").write_text("int newer_symbol(void) { return 0; }\n")
    (tmp_path / "versions.map").write_text("GLIBC_2.34 { global: newer_symbol; };\n")
    (tmp_path / "start.c").write_text(
        "extern int newer_symbol(void); void _start(void) { (void)newer_symbol(); for (;;) {} }\n"
    )
    subprocess.run(
        [
            "cc", "-shared", "-fPIC", "-nostdlib", "-Wl,-soname,libc.so.6",
            "-Wl,--version-script=" + str(tmp_path / "versions.map"),
            "-o", str(tmp_path / "libc.so.6"), str(tmp_path / "newer.c"),
        ],
        check=True,
    )
    subprocess.run(
        ["cc", "-fPIE", "-fno-stack-protector", "-nostdlib", "-c", "-o", str(tmp_path / "start.o"), str(tmp_path / "start.c")],
        check=True,
    )
    subprocess.run(
        [
            "ld", "-pie", "-z", "now", "-z", "relro", "-z", "noexecstack",
            "--dynamic-linker", "/lib64/ld-linux-x86-64.so.2", "-e", "_start",
            "-o", str(tmp_path / "incompatible"), str(tmp_path / "start.o"),
            "-L", str(tmp_path), "-l:libc.so.6",
        ],
        check=True,
    )
    inspected = ABI.inspect_elf(tmp_path / "incompatible")
    assert inspected["required_versions"]["GLIBC"] == ["2.34"]
    assert inspected["offending_symbols"] == [
        {"family": "GLIBC", "version": "2.34", "symbol": "newer_symbol"}
    ]
