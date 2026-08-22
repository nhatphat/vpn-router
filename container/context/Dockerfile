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
COPY capture-dns.sh /usr/local/bin/capture-dns.sh
COPY danted.conf /etc/danted.conf

RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/vpn.exp /usr/local/bin/healthcheck.sh /usr/local/bin/capture-dns.sh

# Declared in the image rather than in the orchestrator, so the container
# reports its own health whether it was started by vpnctl or by compose.
HEALTHCHECK --interval=10s --timeout=3s --retries=3 --start-period=20s \
    CMD /usr/local/bin/healthcheck.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
