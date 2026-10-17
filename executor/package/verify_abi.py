#!/usr/bin/env python3
"""Fail closed when a Mayi Debian package exceeds its supported ABI baseline."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional


VERSION_CEILINGS = {
    "GLIBC": (2, 31),
    "GLIBCXX": (3, 4, 28),
    "CXXABI": (1, 3, 12),
}

# Every dynamic dependency shipped by Mayi must have an explicit package-level
# owner. Unknown SONAMEs fail closed instead of being assumed to exist.
SONAME_PACKAGES = {
    "ld-linux-x86-64.so.2": "libc6",
    "libc.so.6": "libc6",
    "libdl.so.2": "libc6",
    "libgcc_s.so.1": "libgcc-s1",
    "libpam.so.0": "libpam0g",
    "libpthread.so.0": "libc6",
    "libstdc++.so.6": "libstdc++6",
}

VERSION_RE = re.compile(r"\b(GLIBCXX|GLIBC|CXXABI)_([0-9]+(?:\.[0-9]+)+)\b")
NEEDED_RE = re.compile(r"Shared library: \[([^]]+)\]")
DEPENDENCY_NAME_RE = re.compile(r"(?:^|,)\s*([a-z0-9][a-z0-9+.-]*)")


class VerificationError(RuntimeError):
    pass


def run(*args: str) -> str:
    try:
        result = subprocess.run(args, check=True, text=True, capture_output=True)
    except FileNotFoundError as error:
        raise VerificationError(f"required inspection tool is unavailable: {args[0]}") from error
    except subprocess.CalledProcessError as error:
        diagnostic = (error.stderr or error.stdout).strip()
        raise VerificationError(f"{' '.join(args)} failed: {diagnostic}") from error
    return result.stdout


def version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError as error:
        raise VerificationError(f"cannot read packaged file {path}: {error}") from error


def inspect_elf(path: Path) -> dict[str, object]:
    header = run("readelf", "-hW", str(path))
    dynamic = run("readelf", "-dW", str(path))
    program_headers = run("readelf", "-lW", str(path))
    symbols = run("objdump", "-T", str(path))

    elf_type_match = re.search(r"^\s*Type:\s+(\S+)", header, re.MULTILINE)
    elf_type = elf_type_match.group(1) if elf_type_match else "UNKNOWN"
    has_interpreter = " INTERP " in program_headers
    versions: dict[str, set[str]] = {name: set() for name in VERSION_CEILINGS}
    offending_symbols: list[dict[str, str]] = []
    for line in symbols.splitlines():
        for family, version in VERSION_RE.findall(line):
            versions[family].add(version)
            if version_tuple(version) > VERSION_CEILINGS[family]:
                fields = line.split()
                offending_symbols.append(
                    {
                        "family": family,
                        "version": version,
                        "symbol": fields[-1] if fields else "<unknown>",
                    }
                )

    stack_lines = [line for line in program_headers.splitlines() if "GNU_STACK" in line]
    stack_executable = any(re.search(r"\bRWE\b", line) for line in stack_lines)
    needed = sorted(set(NEEDED_RE.findall(dynamic)))
    flags = "\n".join(line for line in dynamic.splitlines() if "FLAGS" in line)

    return {
        "path": str(path),
        "elf_type": elf_type,
        "needed": needed,
        "required_versions": {
            family: sorted(values, key=version_tuple)
            for family, values in versions.items()
            if values
        },
        "offending_symbols": sorted(
            offending_symbols,
            key=lambda item: (item["family"], version_tuple(item["version"]), item["symbol"]),
        ),
        "hardening": {
            "pie": elf_type == "DYN" if has_interpreter else None,
            "relro": "GNU_RELRO" in program_headers,
            "nx_stack": bool(stack_lines) and not stack_executable,
            "bind_now": "BIND_NOW" in dynamic or bool(re.search(r"\bNOW\b", flags)),
        },
    }


def parse_dependency_names(control: str) -> set[str]:
    depends = ""
    collecting = False
    for line in control.splitlines():
        if line.startswith("Depends:"):
            depends = line.removeprefix("Depends:").strip()
            collecting = True
        elif collecting and line.startswith((" ", "\t")):
            depends += " " + line.strip()
        elif collecting:
            break
    return set(DEPENDENCY_NAME_RE.findall(depends))


def validate_report(report: dict[str, object], control: str) -> list[str]:
    errors: list[str] = []
    declared = parse_dependency_names(control)
    elfs = report["elf_files"]
    assert isinstance(elfs, list)
    if not elfs:
        errors.append("package contains no ELF files")
        return errors

    for elf in elfs:
        assert isinstance(elf, dict)
        path = str(elf["path"])
        for item in elf["offending_symbols"]:
            assert isinstance(item, dict)
            ceiling = ".".join(str(part) for part in VERSION_CEILINGS[str(item["family"])])
            errors.append(
                f"{path}: symbol {item['symbol']} requires {item['family']}_{item['version']} "
                f"(ceiling {item['family']}_{ceiling})"
            )
        for soname in elf["needed"]:
            package = SONAME_PACKAGES.get(str(soname))
            if package is None:
                errors.append(f"{path}: runtime library {soname} has no approved package mapping")
            elif package not in declared:
                errors.append(
                    f"{path}: runtime library {soname} requires undeclared package {package}"
                )
        hardening = elf["hardening"]
        assert isinstance(hardening, dict)
        for property_name in ("pie", "relro", "nx_stack", "bind_now"):
            if hardening[property_name] is False:
                errors.append(f"{path}: required hardening property {property_name} is absent")
    if "libc6" not in declared:
        errors.append("package does not declare libc6")
    elif not re.search(r"\blibc6\s*\(>=\s*2\.31\s*\)", control):
        errors.append("package must declare the Debian 11 ABI baseline libc6 (>= 2.31)")
    return errors


def verify_deb(deb: Path) -> dict[str, object]:
    if not deb.is_file():
        raise VerificationError(f"package does not exist: {deb}")
    control = run("dpkg-deb", "-f", str(deb))
    with tempfile.TemporaryDirectory(prefix="mayi-abi-") as temporary:
        root = Path(temporary) / "root"
        root.mkdir()
        run("dpkg-deb", "-x", str(deb), str(root))
        elf_files: list[dict[str, object]] = []
        for path in sorted(root.rglob("*")):
            if path.is_file() and is_elf(path):
                inspected = inspect_elf(path)
                inspected["path"] = "/" + str(path.relative_to(root))
                elf_files.append(inspected)
    report: dict[str, object] = {
        "package": str(deb),
        "ceilings": {
            family: ".".join(str(part) for part in ceiling)
            for family, ceiling in VERSION_CEILINGS.items()
        },
        "elf_files": elf_files,
    }
    report["errors"] = validate_report(report, control)
    report["status"] = "PASS" if not report["errors"] else "FAIL"
    return report


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=Path, help="exact Debian package to inspect")
    parser.add_argument("--json", action="store_true", help="emit machine-readable evidence")
    args = parser.parse_args(argv)
    try:
        report = verify_deb(args.package.resolve())
    except VerificationError as error:
        print(f"ABI verification failed: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for elf in report["elf_files"]:
            versions = elf["required_versions"]
            maxima = ", ".join(
                f"{family}_{values[-1]}" for family, values in versions.items() if values
            )
            print(f"{elf['path']}: {maxima or 'no versioned ABI imports'}")
        for error in report["errors"]:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"ABI verification: {report['status']}")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
