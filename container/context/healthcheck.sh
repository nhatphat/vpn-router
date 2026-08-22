#!/bin/sh
set -eu

ip link show tun0 >/dev/null 2>&1
pgrep -x openvpn >/dev/null 2>&1
pgrep -x danted >/dev/null 2>&1
