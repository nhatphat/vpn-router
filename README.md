# VPN router for macOS

A split-routing setup that combines:

- OpenVPN and a Dante SOCKS5 proxy inside Docker
- a host DNS router for split-horizon DNS
- a host TCP racer for destinations that may or may not require the VPN
- sing-box TUN routing for macOS applications

The public path is fail-open: when the VPN container is unavailable, public traffic can continue directly. Corporate DNS and private destinations fail closed because Dante is protected by an iptables kill-switch.

## Architecture

```text
macOS applications
        |
   sing-box TUN
        |
        +-- private destination ----------> Dante SOCKS5 :1080 -> OpenVPN tun0
        |
        +-- ambiguous TCP -> racer :15080 -+-> direct
        |                                  +-> Dante SOCKS5 -> OpenVPN tun0
        |
        +-- public UDP --------------------> direct

DNS
  sing-box/macOS -> host DNS router :15353
                       +-> public DNS directly
                       +-> VPN-pushed DNS via Dante UDP ASSOCIATE
```

Local listeners bind only to `127.0.0.1` by default.

## Security properties

- Dante traffic can leave the container only through `tun0`.
- If OpenVPN disconnects, Dante is stopped and its direct traffic remains blocked.
- The SOCKS port is published only on host localhost.
- Generated OTP values are not echoed to container logs.
- `.env`, VPN profiles, auth files, logs, and local tooling settings are excluded from Git.
- Secret-bearing local files are also excluded from the Docker build context.

Never commit `.env`, `auth.txt`, or an OpenVPN profile.

## Requirements

- Docker Compose with a runtime that supports `/dev/net/tun`
- Go 1.26 or newer to build the host router
- sing-box 1.13 or newer for the provided configuration
- macOS for the provided TUN and split-resolver examples

The Docker component can also run on Linux. Host interface names and routing integration must then be adjusted for that system.

## 1. Prepare VPN configuration

Copy an OpenVPN profile into the repository:

```bash
cp /path/to/profile.ovpn ./company.ovpn
```

Create the challenge-response auth file:

```bash
cp auth.txt.example auth.txt
```

Create the local environment file:

```bash
cp .env.example .env
```

Set the Base32 TOTP setup secret in `.env`:

```dotenv
TOTP_SECRET=YOUR_BASE32_SECRET
SOCKS_PORT=1080
RETRY_DELAY=5
```

Protect local secrets:

```bash
chmod 600 .env auth.txt company.ovpn
```

## 2. Start the VPN container

```bash
docker compose up -d --build
```

Check status and logs:

```bash
docker compose ps
docker compose logs -f vpn
```

A healthy startup reaches:

```text
VPN tunnel is up (tun0)
SOCKS5 listening on 0.0.0.0:1080
```

The host endpoint is:

```text
127.0.0.1:1080
```

Test it with a destination available through the VPN:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://internal.example.com
```

Use `--socks5-hostname` when hostname resolution must happen through the SOCKS path.

## 3. Build and run the host router

Build a stable binary:

```bash
cd host-dns-router
go build -o host-dns-router .
```

Run it on macOS, replacing `en0` if the physical network interface differs:

```bash
./host-dns-router -bind-interface en0
```

Default endpoints:

```text
127.0.0.1:15353/udp  split-horizon DNS router
127.0.0.1:15080/tcp  direct-vs-VPN SOCKS5 racer
```

The default Compose container name is `vpn-router-vpn-1`. Override it when the Compose project name differs:

```bash
./host-dns-router \
  -bind-interface en0 \
  -container your-project-vpn-1
```

Useful options:

```text
-public-dns              public DNS upstream, default 1.1.1.1:53
-socks                   VPN SOCKS endpoint, default 127.0.0.1:1080
-dns-refresh-interval    interval for reading VPN-pushed DNS servers
-query-timeout           timeout for each DNS branch
-grace-window            wait for a private internal answer after public DNS wins
-dial-timeout             timeout for each TCP racer branch
```

## 4. Run sing-box

Create the local force-VPN rule-set before validating or starting sing-box:

```bash
cp singbox/rules/force-vpn.json.example singbox/rules/force-vpn.json
```

Edit `singbox/rules/force-vpn.json` to force selected domains or macOS
processes through the VPN. Keep domain and process matchers in separate rule
objects: fields inside one rule are combined, while separate rules match
independently.

```json
{
  "version": 4,
  "rules": [
    {
      "domain": ["exact.customer.example"],
      "domain_suffix": ["customer.example"]
    },
    {
      "process_name": ["CustomerApp"]
    },
    {
      "process_path_regex": [
        "^/Applications/CustomerApp\\.app/Contents/.*"
      ]
    }
  ]
}
```

`domain` matches exact hostnames. `domain_suffix` matches both the listed
domain and its subdomains. Process rules include TCP and UDP, so matching apps
fail closed instead of falling back to direct traffic when the VPN is down.
The route configuration sniffs HTTP Host and TLS/QUIC SNI before applying this
rule-set. This is required when a TUN connection arrives with only a destination
IP and has no DNS reverse mapping available to the router.
Delete an unused rule object entirely; an object such as
`{"process_name": []}` is invalid and fails with `missing conditions`.
The local rule file is ignored by Git; do not commit customer domains or local
application details. sing-box 1.10 and newer automatically reload a local
rule-set after the file changes.

Validate the configuration:

```bash
sing-box check -c singbox/config.json
```

Start it after the host router is listening:

```bash
sudo sing-box run -c singbox/config.json
```

The process rule for `host-dns-router` is required. It prevents the router's direct connections from being captured by the TUN again.

## 5. Optional macOS split resolver

To send only one internal DNS suffix to the host DNS router, create a scoped resolver. For example, for `*.corp.example.com`:

```bash
sudo mkdir -p /etc/resolver
printf 'nameserver 127.0.0.1\nport 15353\n' | \
  sudo tee /etc/resolver/corp.example.com >/dev/null
sudo killall mDNSResponder
```

This does not replace Wi-Fi DNS globally. Only names ending in `.corp.example.com` use `127.0.0.1:15353`.

Inspect the active resolver:

```bash
scutil --dns
```

## Failure behavior

### VPN available

- VPN-pushed DNS servers are discovered from `/run/vpn-dns` in the container.
- Internal DNS uses Dante UDP ASSOCIATE through `tun0`.
- Private destinations use the VPN.
- The TCP racer selects and remembers the first successful path.

### VPN unavailable

- Dante becomes unavailable and cannot leak through the container's direct interface.
- Internal DNS and private destinations fail.
- Public DNS continues through the host's direct interface.
- The racer falls back to direct TCP.
- Public Internet remains available while `host-dns-router` and sing-box stay running.

If `host-dns-router` itself stops while sing-box is active, destinations routed to the racer can fail. Start the host router before sing-box.

## Debugging

Inspect the container tunnel and kill-switch:

```bash
docker compose exec vpn ip addr show tun0
docker compose exec vpn ip route
docker compose exec vpn iptables -S OUTPUT
```

Test host DNS:

```bash
dig @127.0.0.1 -p 15353 example.com
```

Test the TCP racer:

```bash
curl --socks5-hostname 127.0.0.1:15080 https://example.com
```

Run Go checks:

```bash
cd host-dns-router
go test ./...
go vet ./...
```

## OTP prompt compatibility

`vpn.exp` recognizes common challenge strings including OTP, verification code, one-time password, token, and challenge prompts containing OTP/token/code.

If a provider uses a different prompt, inspect the non-secret portions of the OpenVPN logs and adjust the regular expression. Never post a TOTP setup secret, generated OTP, auth file, or VPN profile in logs or issue trackers.

## License

MIT. See [LICENSE](LICENSE).
