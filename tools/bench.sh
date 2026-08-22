#!/bin/bash
#
# Measure what the split-routing stack costs, by comparing the same transfer
# through it against one that bypasses it.
#
#   direct  curl --interface en0   leaves through the physical interface,
#                                  skipping the TUN, the racer, everything
#   tun     plain curl             follows the default route into the TUN,
#                                  through sing-box's stack and the racer
#
# Samples alternate between the two, so a change in the network partway
# through hurts both equally instead of one. The address is pinned so both
# reach the same server, and DNS is out of the picture.
#
#   tools/bench.sh
#   HOST=mirror.example.com BIG=50000000 tools/bench.sh
#
# The numbers in the README's "What the stack costs" section come from this.
set -u

HOST=${HOST:-speed.cloudflare.com}
PATH_TEMPLATE=${PATH_TEMPLATE:-/__down?bytes=%d}
SCHEME=${SCHEME:-https}
IFACE=${IFACE:-en0}
BIG=${BIG:-20000000}
SMALL=${SMALL:-1000}
NBIG=${NBIG:-5}
NSMALL=${NSMALL:-15}

LOCAL=$(ipconfig getifaddr "$IFACE") || { echo "no address on $IFACE"; exit 1; }

# Resolved once and pinned, so every sample reaches the same server and no
# sample is paying for a lookup.
IP=$(dig +short "$HOST" A | grep -E '^[0-9]+\.' | head -1)
[ -n "$IP" ] || { echo "could not resolve $HOST"; exit 1; }

port=443; [ "$SCHEME" = http ] && port=80

printf 'target   %s (%s)\n' "$HOST" "$IP"
printf 'local    %s on %s\n' "$LOCAL" "$IFACE"
printf 'vpnctl   %s\n\n' "$(vpnctl version 2>/dev/null | head -1 || echo 'not installed')"

url() { printf "%s://%s$PATH_TEMPLATE" "$SCHEME" "$HOST" "$1"; }

one() {
  local path=$1 bytes=$2 iface=""
  # Not an array: macOS ships bash 3.2, which treats an empty one as unbound
  # under set -u.
  [ "$path" = direct ] && iface="--interface $LOCAL"

  curl -sS -o /dev/null \
    --resolve "$HOST:$port:$IP" \
    $iface \
    -w '%{speed_download} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total}' \
    --max-time 120 "$(url "$bytes")" 2>/dev/null
}

collect() {
  local bytes=$1 count=$2 fd=$3 ft=$4
  : > "$fd"; : > "$ft"
  for i in $(seq 1 "$count"); do
    one direct "$bytes" >> "$fd"; echo >> "$fd"
    one tun    "$bytes" >> "$ft"; echo >> "$ft"
    printf '  sample %d/%d\r' "$i" "$count"
  done
  printf '                    \r'
}

report() {
  python3 - "$@" <<'PY'
import sys, statistics
label, idx, unit, fd, ft = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]

def vals(path):
    out = []
    for line in open(path):
        parts = line.split()
        if len(parts) > idx:
            try:
                out.append(float(parts[idx]))
            except ValueError:
                pass
    return out

d, t = vals(fd), vals(ft)
if not d or not t:
    print(f"  {label:<22} (no data)")
    raise SystemExit

scale = 1 / 1e6 if unit == "MB/s" else 1000 if unit == "ms" else 1
md, mt = statistics.median(d) * scale, statistics.median(t) * scale

if unit == "MB/s":
    delta = f"{(mt / md - 1) * 100:+.0f}%" if md else ""
else:
    delta = f"{mt - md:+.1f} {unit}"

print(f"  {label:<22} direct {md:8.2f}  tun {mt:8.2f}  {unit:<5} {delta}")
PY
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "Throughput: $NBIG x $((BIG / 1000000))MB each way"
collect "$BIG" "$NBIG" "$work/d-big" "$work/t-big"
report "download"           0 MB/s "$work/d-big" "$work/t-big"
report "time to first byte" 3 ms   "$work/d-big" "$work/t-big"

echo
echo "Connection setup: $NSMALL x ${SMALL}B each way"
collect "$SMALL" "$NSMALL" "$work/d-small" "$work/t-small"
report "tcp connect"   1 ms "$work/d-small" "$work/t-small"
report "tls handshake" 2 ms "$work/d-small" "$work/t-small"
report "total"         4 ms "$work/d-small" "$work/t-small"

echo
echo 'Note: "tcp connect" through the TUN is not a speed-up. sing-box completes'
echo 'the handshake locally before any real connection exists, so the cost moves'
echo 'into the TLS handshake. Compare the totals, not that line.'
