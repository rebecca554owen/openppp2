#!/usr/bin/env python3
"""Enforce repository dependency and public API boundaries."""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


SOURCE_SUFFIXES = {".h", ".hpp", ".cpp", ".cc", ".cxx", ".inc"}

GRANDFATHERED_INC_FILES = {
    "ppp/app/client/VEthernetNetworkSwitcherMembers.inc",
    "ppp/app/client/VEthernetNetworkSwitcherPrivateMethods.inc",
    "ppp/app/client/VEthernetNetworkSwitcherProtectedMethods.inc",
    "ppp/app/client/VEthernetNetworkSwitcherPublicMethods.inc",
    "ppp/app/client/VEthernetNetworkSwitcherPublicTypes.inc",
}

MIGRATION_BASELINE = {
    (
        "route/DNS public API exposes concrete host",
        "ppp/app/client/route/RouteHost.h",
    ): 2,
    (
        "route/DNS public API exposes concrete host",
        "ppp/app/client/dns/DnsHost.h",
    ): 8,
    (
        "route/DNS public API exposes concrete host",
        "ppp/app/client/dns/DnsInterceptor.h",
    ): 2,
    (
        "route/DNS public API exposes concrete host",
        "ppp/app/client/dns/DnsUdpRelay.h",
    ): 4,
    (
        "mutable container pointer in public API",
        "ppp/app/client/route/RouteHost.h",
    ): 2,
}

CONCRETE_HOST_PATTERN = re.compile(
    r"\bVEthernet(?:NetworkSwitcher|Exchanger)\b"
)
MUTABLE_CONTAINER_POINTER_PATTERN = re.compile(
    r"\b(?:unordered_(?:map|set)|vector|map|set)\s*<[^;]+>\s*\*"
)
PROTOCOL_REVERSE_INCLUDE_PATTERN = re.compile(
    r"#\s*include\s*[<\"]ppp/app/(?:client|server)/"
)
CLIENT_SERVER_INCLUDE_PATTERN = re.compile(
    r"#\s*include\s*[<\"]ppp/app/server/"
)


@dataclass(frozen=True)
class Candidate:
    path: str
    line_number: int
    rule: str

    def render(self) -> str:
        return f"{self.path}:{self.line_number}: {self.rule}"


def _is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")


def _collect_candidates(root: Path) -> list[Candidate]:
    candidates: list[Candidate] = []
    ppp_root = root / "ppp"
    if not ppp_root.exists():
        return candidates

    for path in sorted(item for item in ppp_root.rglob("*") if item.is_file()):
        if path.suffix not in SOURCE_SUFFIXES:
            continue

        relative = path.relative_to(root).as_posix()
        if path.suffix == ".inc" and relative not in GRANDFATHERED_INC_FILES:
            candidates.append(Candidate(relative, 1, "new .inc declaration fragment"))

        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

        if re.fullmatch(
            r"ppp/app/client/RouteTableManager_(?:linux|darwin|win32|mobile)\.cpp",
            relative,
        ):
            first_code_line = next((line.strip() for line in lines if line.strip()), "")
            if first_code_line != "#include <ppp/stdafx.h>":
                candidates.append(
                    Candidate(relative, 1, "platform source must include stdafx first")
                )

        if relative == "ppp/app/client/route/LinuxRoutePlatform.cpp":
            contents = "\n".join(lines)
            if "entry." in contents and "#include <ppp/net/native/rib.h>" not in contents:
                candidates.append(
                    Candidate(
                        relative,
                        1,
                        "Linux route adapter requires complete RouteEntry",
                    )
                )

        if relative == "ppp/app/client/route/WindowsRoutePlatform.cpp":
            for line_number, line in enumerate(lines, 1):
                if re.search(
                    r"ppp::vector\s*<\s*ppp::string\s*>\s*\{\s*underlying_gateway\s*\}",
                    line,
                ):
                    candidates.append(
                        Candidate(
                            relative,
                            line_number,
                            "Windows gateway crosses string allocator boundary",
                        )
                    )

        for line_number, line in enumerate(lines, 1):
            if relative.startswith("ppp/app/protocol/") and PROTOCOL_REVERSE_INCLUDE_PATTERN.search(line):
                candidates.append(Candidate(relative, line_number, "protocol -> client/server"))

            if relative.startswith("ppp/app/client/") and CLIENT_SERVER_INCLUDE_PATTERN.search(line):
                candidates.append(Candidate(relative, line_number, "client -> server"))

            if (
                relative == "ppp/app/client/RouteTableManager_linux.cpp"
                and "RouteHostPorts" in line
            ):
                candidates.append(
                    Candidate(
                        relative,
                        line_number,
                        "Linux route manager bypasses RouteState",
                    )
                )

            if (
                re.fullmatch(
                    r"ppp/app/client/RouteTableManager(?:_(?:linux|darwin|win32|mobile))?\.(?:h|cpp)",
                    relative,
                )
                and "owner_" in line
                and not _is_comment_line(line)
            ):
                candidates.append(
                    Candidate(
                        relative,
                        line_number,
                        "route manager retains concrete host owner",
                    )
                )

            if "RouteHostPorts" in line:
                candidates.append(
                    Candidate(
                        relative,
                        line_number,
                        "legacy RouteHostPorts service locator",
                    )
                )

            if any(token in line for token in ("DnsHostPorts", "IDnsHost", "dns_host_ports_cache_")):
                candidates.append(
                    Candidate(
                        relative,
                        line_number,
                        "legacy DNS host service locator",
                    )
                )

            is_route_or_dns_header = (
                path.suffix in {".h", ".hpp"}
                and (
                    relative.startswith("ppp/app/client/route/")
                    or relative.startswith("ppp/app/client/dns/")
                )
            )
            if not is_route_or_dns_header or _is_comment_line(line):
                continue

            if CONCRETE_HOST_PATTERN.search(line):
                candidates.append(
                    Candidate(
                        relative,
                        line_number,
                        "route/DNS public API exposes concrete host",
                    )
                )
            if MUTABLE_CONTAINER_POINTER_PATTERN.search(line):
                candidates.append(
                    Candidate(
                        relative,
                        line_number,
                        "mutable container pointer in public API",
                    )
                )

    return candidates


def check_repository(root: Path) -> list[str]:
    grouped: dict[tuple[str, str], list[Candidate]] = defaultdict(list)
    for candidate in _collect_candidates(root):
        grouped[(candidate.rule, candidate.path)].append(candidate)

    violations: list[str] = []
    for key, candidates in sorted(grouped.items()):
        allowed = MIGRATION_BASELINE.get(key, 0)
        violations.extend(candidate.render() for candidate in candidates[allowed:])
    return violations


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    violations = check_repository(root)
    if violations:
        print("Repository layout violations:")
        for violation in violations:
            print(violation)
        return 1
    print("PASS: repository layout boundaries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
