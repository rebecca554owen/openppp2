#!/usr/bin/env python3
"""Verify ppp.vcxproj ClCompile .cpp entries match the CMake library source set.

CMake builds openppp2_lib from recursive globs under ppp/, platform trees,
and selected common/ trees. MSVC uses a hand-maintained list in ppp.vcxproj;
this check fails when they drift (e.g. new ppp/app/client/dns/*.cpp on CMake only).

Usage:
  ./tools/check_vcxproj_sources.py
  ./tools/check_vcxproj_sources.py --vcxproj path/to/ppp.vcxproj
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def normalize(path: str) -> str:
    return path.replace("\\", "/")


def cmake_expected_cpp_sources(root: Path) -> set[str]:
    """Mirror openppp2_lib sources from CMakeLists.txt (Windows / MSVC layout)."""
    expected: set[str] = set()

    common_dirs = (
        "common/aggligator",
        "common/base64",
        "common/chnroutes2",
        "common/json/src",
        "common/libtcpip",
        "common/dnslib",
    )
    for rel in common_dirs:
        expected.update(
            normalize(str(p.relative_to(root)))
            for p in (root / rel).rglob("*.cpp")
            if p.is_file()
        )

    expected.add("common/aesni/aes.cpp")
    expected.update(
        normalize(str(p.relative_to(root)))
        for p in (root / "common/aesni/impl").glob("*.cpp")
    )

    for tree in ("ppp", "windows"):
        expected.update(
            normalize(str(p.relative_to(root)))
            for p in (root / tree).rglob("*.cpp")
            if p.is_file()
        )

    expected.add("main.cpp")
    return expected


def vcxproj_cpp_sources(vcxproj: Path) -> set[str]:
    text = vcxproj.read_text(encoding="utf-8")
    return {
        normalize(match)
        for match in re.findall(r'<ClCompile Include="([^"]+\.cpp)"', text)
    }


def relevant_vcx_extra(vcx: set[str]) -> set[str]:
    prefixes = ("ppp/", "windows/", "common/")
    return {p for p in vcx if p.startswith(prefixes)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--vcxproj",
        type=Path,
        default=Path("ppp.vcxproj"),
        help="MSVC project file to validate (default: ppp.vcxproj)",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Repository root (default: parent of tools/)",
    )
    args = parser.parse_args()

    root = args.root or Path(__file__).resolve().parent.parent
    vcxproj = args.vcxproj if args.vcxproj.is_absolute() else root / args.vcxproj

    if not vcxproj.is_file():
        print(f"FAIL: vcxproj not found: {vcxproj}", file=sys.stderr)
        return 1

    expected = cmake_expected_cpp_sources(root)
    vcx = vcxproj_cpp_sources(vcxproj)

    missing = sorted(expected - vcx)
    extra = sorted(relevant_vcx_extra(vcx) - expected)

    print(f"INFO: cmake-equivalent .cpp sources = {len(expected)}")
    print(f"INFO: ppp.vcxproj ClCompile .cpp entries = {len(vcx)}")

    if missing:
        print(f"FAIL: {len(missing)} .cpp file(s) in CMake layout but missing from vcxproj:")
        for path in missing:
            print(f"  - {path}")

    if extra:
        print(f"FAIL: {len(extra)} .cpp file(s) in vcxproj but not in CMake layout:")
        for path in extra:
            print(f"  - {path}")

    if missing or extra:
        return 1

    print("PASS: vcxproj .cpp sources match CMake layout")
    return 0


if __name__ == "__main__":
    sys.exit(main())
