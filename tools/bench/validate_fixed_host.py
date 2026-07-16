#!/usr/bin/env python3
import json
from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: validate_fixed_host.py ENV_JSON EXPECTED_HOST_ID", file=sys.stderr)
        return 2

    environment = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    if str(environment.get("virt", "")).lower() == "wsl":
        print("WSL is diagnostic-only and cannot provide a fixed-host baseline", file=sys.stderr)
        return 1
    if environment.get("arch") not in ("x86_64", "amd64"):
        print("fixed-host baselines require Linux x86-64", file=sys.stderr)
        return 1
    if environment.get("governor") != "performance":
        print("fixed-host baselines require the performance governor", file=sys.stderr)
        return 1
    if environment.get("perf_cycles") is not True:
        print("fixed-host baselines require readable perf cycles", file=sys.stderr)
        return 1
    if not sys.argv[2] or environment.get("host_id") != sys.argv[2]:
        print("environment host_id does not match the expected fixed host", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
