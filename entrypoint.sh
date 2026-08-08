#!/bin/bash
set -uo pipefail

VPN_CONFIG="${VPN_CONFIG:-/config/company.ovpn}"
VPN_AUTH_FILE="${VPN_AUTH_FILE:-/config/auth.txt}"
RETRY_DELAY="${RETRY_DELAY:-5}"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

cleanup_socks() {
  if [[ -n "${SOCKS_PID:-}" ]] && kill -0 "$SOCKS_PID" 2>/dev/null; then
    kill "$SOCKS_PID" 2>/dev/null || true
    wait "$SOCKS_PID" 2>/dev/null || true
  fi

  SOCKS_PID=""
}

cleanup_all() {
  cleanup_socks

  if [[ -n "${VPN_PID:-}" ]] && kill -0 "$VPN_PID" 2>/dev/null; then
    kill "$VPN_PID" 2>/dev/null || true
    wait "$VPN_PID" 2>/dev/null || true
  fi
}

trap cleanup_all EXIT INT TERM

if [[ ! -c /dev/net/tun ]]; then
  log "ERROR: /dev/net/tun is unavailable. Run with --device=/dev/net/tun and NET_ADMIN."
  exit 1
fi

if [[ ! -r "$VPN_CONFIG" ]]; then
  log "ERROR: VPN config not found/readable: $VPN_CONFIG"
  exit 1
fi

if [[ ! -r "$VPN_AUTH_FILE" ]]; then
  log "ERROR: auth file not found/readable: $VPN_AUTH_FILE"
  exit 1
fi

if [[ -z "${TOTP_SECRET:-}" ]]; then
  log "ERROR: TOTP_SECRET is empty"
  exit 1
fi

#
# SOCKS kill-switch
#
# microsocks runs as user "socks".
#
# Allow:
#   1. replies for already-established connections
#   2. loopback traffic (Docker DNS / local traffic)
#   3. new outbound connections through tun0
#
# Reject everything else from microsocks.
#
# OpenVPN itself runs as root, so these rules do not affect
# its connection to the VPN server over eth0.
#

SOCKS_UID="$(id -u socks)"

log "Installing SOCKS kill-switch for uid=$SOCKS_UID"

# Remove old rule from previous version if present.
while iptables -D OUTPUT \
  -m owner --uid-owner "$SOCKS_UID" \
  ! -o tun0 \
  -j REJECT 2>/dev/null; do
  :
done

# Avoid duplicate rules in case entrypoint logic is ever re-run.
iptables -D OUTPUT \
  -m owner --uid-owner "$SOCKS_UID" \
  -m conntrack --ctstate ESTABLISHED,RELATED \
  -j ACCEPT 2>/dev/null || true

iptables -D OUTPUT \
  -m owner --uid-owner "$SOCKS_UID" \
  -o lo \
  -j ACCEPT 2>/dev/null || true

iptables -D OUTPUT \
  -m owner --uid-owner "$SOCKS_UID" \
  -o tun0 \
  -j ACCEPT 2>/dev/null || true

iptables -D OUTPUT \
  -m owner --uid-owner "$SOCKS_UID" \
  -j REJECT 2>/dev/null || true

# Allow microsocks replies back to the SOCKS client.
iptables -A OUTPUT \
  -m owner --uid-owner "$SOCKS_UID" \
  -m conntrack --ctstate ESTABLISHED,RELATED \
  -j ACCEPT

# Allow loopback traffic.
iptables -A OUTPUT \
  -m owner --uid-owner "$SOCKS_UID" \
  -o lo \
  -j ACCEPT

# Allow SOCKS outbound traffic only through VPN.
iptables -A OUTPUT \
  -m owner --uid-owner "$SOCKS_UID" \
  -o tun0 \
  -j ACCEPT

# Block any direct traffic through eth0 or another interface.
iptables -A OUTPUT \
  -m owner --uid-owner "$SOCKS_UID" \
  -j REJECT

log "SOCKS kill-switch installed"

while true; do
  cleanup_socks
  rm -f /run/vpn-ready

  log "Starting OpenVPN..."

  /usr/local/bin/vpn.exp &
  VPN_PID=$!

  # Wait until tun0 exists, or OpenVPN exits.
  while true; do
    if ! kill -0 "$VPN_PID" 2>/dev/null; then
      wait "$VPN_PID" 2>/dev/null || true

      log "OpenVPN exited before tun0 became ready; retrying in ${RETRY_DELAY}s"
      break
    fi

    if ip link show tun0 >/dev/null 2>&1; then
      log "VPN tunnel is up (tun0)"

      touch /run/vpn-ready

      #
      # Run SOCKS as restricted user.
      #
      # Kill-switch guarantees:
      #
      #   VPN up   -> SOCKS traffic via tun0
      #   VPN down -> SOCKS traffic blocked
      #
      runuser -u socks -- \
        microsocks \
        -i 0.0.0.0 \
        -p 1080 &

      SOCKS_PID=$!

      log "SOCKS5 listening on 0.0.0.0:1080"

      #
      # Stay here while VPN is alive.
      #
      while kill -0 "$VPN_PID" 2>/dev/null; do

        #
        # If tun0 disappears, immediately stop SOCKS.
        #
        if ! ip link show tun0 >/dev/null 2>&1; then
          log "tun0 disappeared; stopping SOCKS and reconnecting VPN"

          cleanup_socks

          kill "$VPN_PID" 2>/dev/null || true
          wait "$VPN_PID" 2>/dev/null || true

          break
        fi

        #
        # Restart microsocks if it crashes while VPN is still alive.
        #
        if [[ -n "${SOCKS_PID:-}" ]] && \
           ! kill -0 "$SOCKS_PID" 2>/dev/null; then

          log "SOCKS process exited; restarting it"

          runuser -u socks -- \
            microsocks \
            -i 0.0.0.0 \
            -p 1080 &

          SOCKS_PID=$!
        fi

        sleep 1
      done

      cleanup_socks
      rm -f /run/vpn-ready

      if kill -0 "$VPN_PID" 2>/dev/null; then
        kill "$VPN_PID" 2>/dev/null || true
      fi

      wait "$VPN_PID" 2>/dev/null || true

      log "VPN disconnected; retrying in ${RETRY_DELAY}s"
      break
    fi

    sleep 1
  done

  sleep "$RETRY_DELAY"
done
