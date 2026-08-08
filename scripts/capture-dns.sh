#!/bin/sh

env | grep '^foreign_option_' |
while IFS='=' read -r key value; do
  case "$value" in
    "dhcp-option DNS "*)
      echo "${value#dhcp-option DNS }"
      ;;
  esac
done > /run/vpn-dns