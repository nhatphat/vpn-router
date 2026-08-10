FROM debian:bookworm-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    openvpn \
    oathtool \
    expect \
    dante-server \
    iproute2 \
    iptables \
    procps \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --no-create-home --shell /usr/sbin/nologin socks

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY vpn.exp /usr/local/bin/vpn.exp
COPY healthcheck.sh /usr/local/bin/healthcheck.sh
COPY scripts/capture-dns.sh /usr/local/bin/capture-dns.sh
COPY danted.conf /etc/danted.conf

RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/vpn.exp /usr/local/bin/healthcheck.sh /usr/local/bin/capture-dns.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
