#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== Path: client cpp -> server cpp (expect 0) ==="
if [[ -f .gitnexus/run.cjs ]]; then
  node .gitnexus/run.cjs cypher "MATCH (caller)-[:CodeRelation {type: 'CALLS'}]->(callee)
WHERE caller.filePath STARTS WITH 'ppp/app/client/'
  AND callee.filePath STARTS WITH 'ppp/app/server/'
RETURN count(*) AS calls" 2>/dev/null || true
else
  npx gitnexus cypher "MATCH (caller)-[:CodeRelation {type: 'CALLS'}]->(callee)
WHERE caller.filePath STARTS WITH 'ppp/app/client/'
  AND callee.filePath STARTS WITH 'ppp/app/server/'
RETURN count(*) AS calls" 2>/dev/null || true
fi

echo "=== AppConfiguration.h include count ==="
echo -n "ppp_headers="
(grep -r '#include <ppp/configurations/AppConfiguration.h>' ppp/ --include='*.h' 2>/dev/null || true) | wc -l | tr -d ' '
echo -n "ppp_all="
(grep -r '#include <ppp/configurations/AppConfiguration.h>' ppp/ --include='*.h' --include='*.cpp' 2>/dev/null || true) | wc -l | tr -d ' '
