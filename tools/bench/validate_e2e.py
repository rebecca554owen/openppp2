#!/usr/bin/env python3
import json
import sys
from pathlib import Path


document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if document.get("error"):
    raise SystemExit(f"iperf3 failed: {document['error']}")

end = document.get("end", {})
metrics = end.get("sum") or end.get("sum_sent") or {}
seconds = metrics.get("seconds") or 0
packets = metrics.get("packets") or 0
if seconds <= 0 or packets <= 0:
    raise SystemExit("iperf3 result contains no completed UDP packets")

json.dump(
    {
        "seconds": seconds,
        "packets": packets,
        "pps": packets / seconds,
        "lost_packets": metrics.get("lost_packets"),
        "lost_percent": metrics.get("lost_percent"),
        "bits_per_second": metrics.get("bits_per_second"),
    },
    sys.stdout,
    indent=2,
    sort_keys=True,
)
print()
