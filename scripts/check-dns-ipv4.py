#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Read-only IPv4 format validator for PPP_PUBLIC_DNS_SERVER_LIST.

Extracts the DNS server list from ppp/stdafx.h, resolves the two
PPP_PREFERRED_DNS_SERVER_* macros, and validates every entry against
a strict IPv4 format (4 octets, each 0-255, no leading zeros like "01").

Exit codes:
  0 = all entries valid
  1 = one or more entries failed validation
  2 = extraction / parse error (could not find the array or macros)

This script is intentionally:
  - Read-only  (never modifies any file)
  - Offline    (no network access)
  - Standalone (no third-party dependencies beyond Python 3 stdlib)
  - Non-gating (meant for ad-hoc / manual runs, NOT wired into CI)

Usage:
  python3 scripts/check-dns-ipv4.py                  # auto-locate ppp/stdafx.h
  python3 scripts/check-dns-ipv4.py path/to/stdafx.h # explicit path
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# IPv4 validation
# ---------------------------------------------------------------------------

# Strict: 4 dot-separated groups of 1-3 digits, each 0-255, no leading zeros.
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)$"
)


def is_valid_ipv4(addr: str) -> bool:
    """Return True if *addr* is a well-formed IPv4 dotted-quad."""
    return _IPV4_RE.match(addr) is not None


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

_MACRO_RE = re.compile(
    r'^\s*#\s*define\s+PPP_PREFERRED_DNS_SERVER_[12]\s+"([^"]+)"',
    re.MULTILINE,
)

# Matches a bare string literal or a macro identifier inside the array init.
_ENTRY_RE = re.compile(
    r"""
    "(?P<literal>[^"]+)"          # quoted string literal
    |
    (?P<macro>PPP_PREFERRED_DNS_SERVER_[12])  # or macro identifier
    """,
    re.VERBOSE,
)

_BEGIN_MARKER = "// ---- PPP_PUBLIC_DNS_SERVER_LIST begins ----"
_END_MARKER = "// ---- PPP_PUBLIC_DNS_SERVER_LIST ends ----"


def parse_dns_list(src: str) -> list[str]:
    """Return the raw list of string literals / macro names from the array."""

    # 1. Resolve macros -------------------------------------------------------
    macros: dict[str, str] = {}
    for m in _MACRO_RE.finditer(src):
        # The macro name is the second whitespace-separated token after #define.
        # Simpler: re-extract from the matched line.
        line = m.group(0)
        name_match = re.search(r"(PPP_PREFERRED_DNS_SERVER_[12])", line)
        if name_match:
            macros[name_match.group(1)] = m.group(1)

    # 2. Locate the array body ------------------------------------------------
    begin = src.find(_BEGIN_MARKER)
    end = src.find(_END_MARKER)
    if begin == -1 or end == -1:
        raise RuntimeError(
            "Cannot find PPP_PUBLIC_DNS_SERVER_LIST boundary markers "
            "in the source file."
        )
    body = src[begin:end]

    # Scope to the actual initializer: find the opening '{' and closing '}'
    # to avoid matching macro names in comments above the array.
    brace_open = body.find("{")
    brace_close = body.rfind("}")
    if brace_open == -1 or brace_close == -1:
        raise RuntimeError(
            "Cannot find array initializer braces '{' / '}' inside "
            "PPP_PUBLIC_DNS_SERVER_LIST boundary markers."
        )
    body = body[brace_open:brace_close]

    # 3. Extract entries ------------------------------------------------------
    entries: list[str] = []
    for m in _ENTRY_RE.finditer(body):
        if m.group("literal") is not None:
            entries.append(m.group("literal"))
        else:
            macro_name = m.group("macro")
            if macro_name not in macros:
                raise RuntimeError(
                    f"Array references macro '{macro_name}' but its "
                    f"#define was not found in the file."
                )
            entries.append(macros[macro_name])

    if not entries:
        raise RuntimeError("Extracted zero entries from the DNS list array.")

    return entries


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    # Locate the header file --------------------------------------------------
    if len(sys.argv) > 1:
        header = Path(sys.argv[1])
    else:
        # Walk up from this script to the repo root, then into ppp/.
        repo_root = Path(__file__).resolve().parent.parent
        header = repo_root / "ppp" / "stdafx.h"

    if not header.is_file():
        print(f"ERROR: file not found: {header}", file=sys.stderr)
        return 2

    src = header.read_text(encoding="utf-8", errors="replace")

    # Parse -------------------------------------------------------------------
    try:
        entries = parse_dns_list(src)
    except RuntimeError as exc:
        print(f"PARSE ERROR: {exc}", file=sys.stderr)
        return 2

    # Validate ----------------------------------------------------------------
    print(f"Checking {len(entries)} DNS server entries in {header} ...\n")

    bad: list[tuple[int, str, str]] = []  # (1-based index, raw, reason)
    for idx, raw in enumerate(entries, start=1):
        if not is_valid_ipv4(raw):
            bad.append((idx, raw, "invalid IPv4 format"))
        # Additional sanity: reject 0.0.0.0 and 255.255.255.255
        elif raw in ("0.0.0.0", "255.255.255.255"):
            bad.append((idx, raw, "reserved / unusable address"))

    # Report ------------------------------------------------------------------
    if bad:
        print(f"FAIL  — {len(bad)} entry/entries failed validation:\n")
        for idx, raw, reason in bad:
            print(f"  [{idx:>2}] {raw!r:30s}  ← {reason}")
        print(
            f"\nPlease fix the entries above in {header} and "
            f"update the static_assert count if needed."
        )
        return 1

    print(f"OK    — all {len(entries)} entries are valid IPv4 addresses.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
