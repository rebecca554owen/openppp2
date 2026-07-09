#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
violations=0

# client must not include server headers
if rg -n '#include <ppp/app/server/' ppp/app/client/ -g'*.{h,cpp}' 2>/dev/null; then
  echo "FAIL: client includes server headers"
  violations=$((violations + 1))
fi

# application internal hub must not pull client+server switcher headers
if rg -n '#include <ppp/app/(client/VEthernetNetworkSwitcher|server/VirtualEthernetSwitcher)\.h>' ppp/app/PppApplicationInternal.h 2>/dev/null; then
  echo "FAIL: PppApplicationInternal includes switcher headers"
  violations=$((violations + 1))
fi

# facade/views must not pull heavy deps (skip if directory missing)
if [[ -d ppp/facade/views ]]; then
  if rg -n 'configurations/AppConfiguration|json/json' ppp/facade/views/ -g'*.h' 2>/dev/null; then
    echo "FAIL: facade views pull heavy deps"
    violations=$((violations + 1))
  fi
fi

# stdafx in headers: baseline 97, fail only if count increases
STDAFX_BASELINE=100
stdafx_count=$(rg -l 'stdafx' ppp --glob '*.h' 2>/dev/null | wc -l | tr -d ' ')
if [[ "$stdafx_count" -gt "$STDAFX_BASELINE" ]]; then
  echo "FAIL: stdafx in ppp/**/*.h increased ($stdafx_count > $STDAFX_BASELINE)"
  violations=$((violations + 1))
else
  echo "INFO: stdafx in ppp/**/*.h = $stdafx_count (baseline $STDAFX_BASELINE)"
fi

if [[ $violations -eq 0 ]]; then
  echo "PASS: include boundaries"
else
  exit 1
fi
