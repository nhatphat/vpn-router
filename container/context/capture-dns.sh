#!/bin/sh
#
# OpenVPN --up script: record the DNS servers the server pushed.
#
# Written twice on purpose. /run/vpn-dns is the in-container copy, kept for
# compatibility with anything that reads it from inside. /run/shared is a bind
# mount from the host, which lets the host-side DNS router read the servers
# straight off the filesystem rather than having to execute a command in the
# container.

set -u

servers() {
  env | grep '^foreign_option_' |
  while IFS='=' read -r key value; do
    case "$value" in
      "dhcp-option DNS "*)
        echo "${value#dhcp-option DNS }"
        ;;
    esac
  done
}

servers > /run/vpn-dns

if [ -d /run/shared ]; then
  cp /run/vpn-dns /run/shared/vpn-dns.tmp && mv /run/shared/vpn-dns.tmp /run/shared/vpn-dns
fi