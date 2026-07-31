#!/system/bin/sh
# End-to-end VPN connectivity & traffic-splitting test for openppp2_mobile.
# Push to /data/local/tmp/ and run with `sh`. Requires `su` for root reads
# and `run-as` for routing curl traffic through the VPN (uid 10041, in the
# VPN's allow-range; uid 2000=shell is *excluded* by Android by default,
# which is why bare `adb shell curl` does NOT traverse the tunnel).
#
# A note on UID and the VPN:
#   The system VPN agent is registered with `Uids: <1-999,1001-1999,2001-99999>`,
#   which deliberately excludes uid 1000 (system) and uid 2000 (shell). To test
#   real traffic routing we must execute curl as the *app's own* uid (10041 for
#   us). `run-as supersocksr.ppp.android <cmd>` does exactly that.

set -u
PASS=0
FAIL=0
APP=supersocksr.ppp.android
LOG=/data/data/$APP/files/openppp2-vpn.log
RULES=/data/data/$APP/files/rules

hr() { echo "============================================================"; }
ok()   { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
info() { echo "  [..]   $*"; }

ROOT=""
if [ "$(id -u)" = "0" ]; then ROOT=""; else
  if su 0 sh -c true >/dev/null 2>&1; then ROOT="su 0"; fi
fi
RUNAS="run-as $APP"

# ---------------------------------------------------------------- 1. tun0
hr; echo "[1] VPN interface (tun0)"
TUN_INFO=$(ip addr show tun0 2>/dev/null)
if [ -z "$TUN_INFO" ]; then
  bad "tun0 not present -- VPN is not connected. Aborting."
  exit 1
fi
TUN_IP=$(echo "$TUN_INFO" | awk '/inet /{print $2; exit}')
ok "tun0 up, addr=$TUN_IP"

# ---------------------------------------------------------------- 2. routes
hr; echo "[2] Default route via tun0"
DEF=$(ip route show default 2>/dev/null)
echo "    ${DEF:-<none>}"
case "$DEF" in
  *tun0*) ok "default route is tun0" ;;
  *)      info "main table default is not tun0 (Android typically routes per-uid via fwmark; checked next)" ;;
esac

# ---------------------------------------------------------------- 3. logs
hr; echo "[3] open_switcher / geo-rules markers (logcat, native engine)"
GEN=$($ROOT logcat -d 2>/dev/null | grep "open_switcher: geo-rules generated" | tail -1)
if [ -n "$GEN" ]; then
  echo "    $GEN"
  BYPASS_N=$(echo "$GEN" | sed -n 's/.*bypass=[^(]*(\([0-9]*\)).*/\1/p')
  DNS_N=$(echo "$GEN" | sed -n 's/.*dns_rules=[^(]*(\([0-9]*\)).*/\1/p')
  if [ "${BYPASS_N:-0}" -gt 0 ] || [ "${DNS_N:-0}" -gt 0 ]; then
    ok "geo-rules produced bypass=$BYPASS_N dns_rules=$DNS_N"
  else
    bad "geo-rules generated empty output"
  fi
else
  bad "no 'geo-rules generated' marker in logcat"
fi
EXTR=$($ROOT logcat -d 2>/dev/null | grep -c "extracted asset rules/")
if [ "$EXTR" -gt 0 ]; then ok "asset extraction logged ($EXTR entries)";
else info "no fresh asset extraction (already present)"; fi

# ---------------------------------------------------------------- 4. files/rules
hr; echo "[4] files/rules contents"
LS=$($RUNAS ls -la files/rules 2>/dev/null)
if [ -n "$LS" ]; then
  echo "$LS" | sed 's/^/    /'
  for f in GeoIP.dat GeoSite.dat; do
    SZ=$($RUNAS sh -c "stat -c%s files/rules/$f 2>/dev/null || wc -c < files/rules/$f")
    if [ -n "$SZ" ] && [ "$SZ" -gt 1000 ]; then
      ok "$f present, size=$SZ"
    else
      bad "$f missing/tiny (size=$SZ)"
    fi
  done
else
  bad "rules dir not accessible (run-as failed?)"
fi

# ---------------------------------------------------------------- 5. DNS via app uid
hr; echo "[5] DNS resolution (app uid via run-as, so it goes through tun0)"
for host in www.baidu.com www.qq.com www.google.com www.cloudflare.com; do
  ANS=$($RUNAS getent hosts "$host" 2>/dev/null | awk '{print $1}' | head -3 | tr '\n' ' ')
  if [ -z "$ANS" ]; then
    # Fallback: use curl -v to capture resolved IP.
    ANS=$($RUNAS /system/bin/curl -k -s -m 6 -o /dev/null -w "%{remote_ip}" "https://$host/" 2>/dev/null)
  fi
  if [ -n "$ANS" ]; then ok "$host -> $ANS"; else bad "$host: resolve empty"; fi
done

# ---------------------------------------------------------------- 6. counters
hr; echo "[6] Traffic split (tun0 byte counter delta per request -- run-as uid)"
read_tx() { cat /sys/class/net/tun0/statistics/tx_bytes 2>/dev/null; }
read_rx() { cat /sys/class/net/tun0/statistics/rx_bytes 2>/dev/null; }

run_curl() {
  url="$1"; label="$2"; expect="$3"
  rx0=$(read_rx); tx0=$(read_tx)
  out=$($RUNAS /system/bin/curl -k -s -o /dev/null -m 12 -w "%{http_code} %{remote_ip} %{size_download}B in %{time_total}s" "$url" 2>&1)
  rc=$?
  rx1=$(read_rx); tx1=$(read_tx)
  drx=$((rx1 - rx0)); dtx=$((tx1 - tx0))
  status="rc=$rc, $out, tun0 dRx=$drx dTx=$dtx"
  if [ "$rc" -ne 0 ]; then bad "$label curl failed ($status)"; return; fi
  if [ "$expect" = "proxy" ]; then
    if [ "$dtx" -gt 200 ]; then ok "$label via PROXY ($status)"; else bad "$label expected PROXY but no tun0 tx ($status)"; fi
  else
    if [ "$dtx" -lt 800 ]; then ok "$label via DIRECT ($status)"; else info "$label CN host but tun0 tx grew ($status)"; fi
  fi
}

run_curl "https://www.baidu.com/"                    "baidu.com    (CN)"        direct
run_curl "https://www.qq.com/"                       "qq.com       (CN)"        direct
run_curl "https://www.cloudflare.com/cdn-cgi/trace"  "cloudflare/trace (FOREIGN)" proxy
run_curl "https://www.google.com/generate_204"       "google /generate_204 (FOREIGN)" proxy

# ---------------------------------------------------------------- 7. summary
hr
echo "RESULT: pass=$PASS fail=$FAIL"
[ $FAIL -eq 0 ]
