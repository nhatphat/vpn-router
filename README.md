# Company VPN -> SOCKS5 container

Runs an OpenVPN client inside Docker, automatically generates TOTP/OTP from a Base32 setup secret, reconnects forever on failure/disconnect, and exposes a SOCKS5 proxy on the host.

The SOCKS process is protected by an iptables kill-switch: traffic originating from the SOCKS process is allowed only through `tun0`. If the VPN is down, SOCKS traffic fails instead of leaking through the container's normal Internet route.

## Architecture

```text
Host
  |
  +-- 127.0.0.1:1080 (SOCKS5)
            |
         Docker container
            |
         OpenVPN full tunnel
            |
           tun0
            |
      Company/internal network
```

Later, sing-box on the host can route selected domains/IPs to `127.0.0.1:1080` and keep everything else direct.

## 1. Prepare files

Copy your OpenVPN profile into this folder:

```bash
cp /path/to/your/profile.ovpn ./company.ovpn
```

Create the dummy username/password file:

```bash
cp auth.txt.example auth.txt
```

`auth.txt` must contain exactly two lines:

```text
dummy
dummy
```

Create `.env`:

```bash
cp .env.example .env
```

Edit `.env` and replace the example secret with your real Base32 TOTP setup secret:

```dotenv
TOTP_SECRET=YOUR_BASE32_SECRET
SOCKS_PORT=1080
RETRY_DELAY=5
```

Protect secrets:

```bash
chmod 600 .env auth.txt company.ovpn
```

Do not commit `.env`, `auth.txt`, or `company.ovpn`.

## 2. Start

```bash
docker compose up -d --build
```

Watch logs:

```bash
docker compose logs -f vpn
```

Expected flow:

```text
Starting OpenVPN...
... OTP prompt ...
VPN tunnel is up (tun0)
SOCKS5 listening on 0.0.0.0:1080
```

The port is published only on host localhost:

```text
127.0.0.1:1080
```

It is not exposed to your LAN by default.

## 3. Test SOCKS

If normal public Internet is allowed through the company VPN:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

For an internal domain:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://internal.example.com
```

Important: use `--socks5-hostname`, not `--socks5`, if you want DNS resolution to happen through the SOCKS side instead of on the host.

## 4. Auto-recovery behavior

The setup automatically handles:

- host reboot -> Docker starts container -> VPN connects
- container restart -> VPN reconnects
- authentication/network failure -> retry forever every `RETRY_DELAY` seconds
- VPN disconnect -> SOCKS stops -> VPN reconnects -> SOCKS starts again
- each OTP challenge -> a fresh TOTP is generated
- SOCKS traffic while VPN is down -> rejected by kill-switch; no direct fallback

`restart: unless-stopped` handles container/process crashes. `entrypoint.sh` additionally handles OpenVPN reconnects inside the running container.

## 5. Status / debugging

Container status:

```bash
docker compose ps
```

Check `tun0`:

```bash
docker exec company-vpn-socks ip addr show tun0
```

Check routes:

```bash
docker exec company-vpn-socks ip route
```

Check kill-switch:

```bash
docker exec company-vpn-socks iptables -S OUTPUT
```

Generate a TOTP manually inside the container (debug only):

```bash
docker compose exec vpn sh -lc 'oathtool --totp --base32 "$TOTP_SECRET"'
```

## OTP prompt compatibility

`vpn.exp` currently detects prompts containing common strings such as:

- OTP
- verification code
- one-time password
- token
- challenge ... OTP/token/code

If your VPN server uses an unusual OpenVPN challenge format, run:

```bash
docker compose logs -f vpn
```

and adjust the regex in `vpn.exp` to the exact prompt. Do not post your real TOTP secret in logs or issue trackers.

## macOS note

Docker Desktop provides `/dev/net/tun` differently from native Linux containers. This project is primarily suitable for a Linux Docker host. If your target host is macOS with Docker Desktop, OpenVPN-in-Docker networking may require a different approach (for example a VPN container image designed for Docker Desktop or running the VPN on a Linux VM).
