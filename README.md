# vpnctl

Split routing for macOS: corporate traffic through an OpenVPN tunnel, everything
else straight out of the physical interface, decided per destination rather than
per application.

One binary supervises the whole thing. One configuration file describes it.

```bash
sudo vpnctl install     # once
vpnctl setup            # point it at your VPN profile
vpnctl status           # any time, no password
```

## What it does

Some destinations are only reachable from inside a VPN. Most are not. Routing
everything through the tunnel is slow and sends personal traffic through a
corporate gateway; routing nothing through it makes the VPN useless. So the
decision is made per destination, and made without anyone maintaining a list.

Two mechanisms do that:

- **Every DNS lookup is resolved twice, in parallel** — once against a public
  resolver, once against the DNS servers the VPN pushed. A private-IP answer
  from the corporate side wins, which makes the destination route itself.
- **For addresses that look public but are only reachable inside the tunnel**,
  both paths are dialled at once and the first to connect wins, then remembered
  for that destination.

Measured against the same transfer bypassing the stack entirely, throughput is
indistinguishable and a new connection costs a few milliseconds more.
`tools/bench.sh` is what measures it.

## Requirements

- macOS, Apple silicon or Intel
- A container runtime with `/dev/net/tun`: OrbStack, Docker Desktop or colima.
  It is **not** installed for you, and it runs in your login session, so the VPN
  is unavailable until you log in. Public traffic works regardless.
- An OpenVPN profile, its credentials, and the Base32 TOTP secret for its
  one-time-code challenge

sing-box is installed for you.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/nhatphat/vpn-router/main/install.sh | sh
```

That downloads the latest release, checks it against the checksum published
beside it, and runs `vpnctl install`, which asks for your password once — a
fingerprint if you have `pam_tid.so` in `/etc/pam.d/sudo_local`. The script is
short and worth reading before you pipe it to a shell.

Only Apple silicon is published. On an Intel Mac, or to run your own build:

```bash
go build -trimpath -o vpnctl ./cmd/vpnctl
sudo ./vpnctl install
```

Installing copies vpnctl and a root-owned sing-box into
`/usr/local/libexec/vpnctl/`, writes `~/.config/vpnctl/config.yaml` if you have
none, builds the VPN image from a build context embedded in the binary, and
starts a LaunchDaemon. Nothing after that needs a password: the daemon is
resident, so it comes back after a reboot before anyone logs in, and restarts
from the CLI or the menu bar are immediate.

Then point it at your VPN:

```bash
vpnctl setup
```

It asks for the path to your `.ovpn` profile, your username and password, and
the Base32 TOTP secret, then writes all three into `~/.config/vpnctl/` with the
right permissions and recreates the container. No `sudo`: these are your
credentials, in your own directory.

The secret is checked while you type it, because a mistyped secret is otherwise
indistinguishable from a wrong password or a server problem, and only shows up
as a VPN that will not connect:

```
  That secret produces 287082 right now, valid for 16 more seconds.
  Does that match your authenticator? [Y/n]:
```

Finish with `vpnctl doctor`, which checks the installation and prints the fix
for anything it finds.

### Updating

`sudo vpnctl update` fetches the newest release, verifies it against the
published checksum, and hands over to its own installer, so an upgrade takes the
same path a fresh install does. `vpnctl update -check` only looks.

The menu bar offers the same thing as an item, and says which version you are on
when there is nothing to install. It asks GitHub when you open the menu rather
than on a timer, at most once an hour. Clicking it brings up the system's
authorisation dialog: replacing a root-owned binary is not something a process
running as you should do quietly.

## Everyday use

| Command | What it does |
|---|---|
| `vpnctl status` | what every component is doing; `-w` to follow |
| `vpnctl logs` | one merged, tagged log; `-f` to follow, `-source vpn\|singbox\|dns\|racer\|supervisor` |
| `vpnctl doctor` | check the installation and print the fix for anything wrong |
| `vpnctl setup` | point it at a `.ovpn` profile and your credentials |
| `vpnctl reload` | apply an edited config, restarting only what changed |
| `vpnctl resolver [on\|off <domain>]` | list scoped resolver domains, or switch one |
| `vpnctl restart <component>` | `vpn`, `singbox`, `dns-router`, `racer`, or `all` |
| `vpnctl retry` | leave safe mode after the breaker gave up on sing-box |
| `vpnctl stop` / `start` | switch the whole stack off and on, removing nothing |
| `sudo vpnctl update` | install the newest release; `-check` only reports |

None of these need `sudo` except `update`.

**The menu bar** is installed by default and starts at login. It shows the state
as `✅ VPN`, `⚠️ VPN`, `❌ VPN` or `⏸️ VPN`; stops and starts the stack, restarts
any component, applies an edited config, switches scoped resolver domains on and
off, and opens the log page. **Quit menu bar** quits only the menu bar — the
daemon and the tunnel keep running, which is why it is not called "Quit" — so
bring it back with `vpnctl menubar -start` or by logging in again.
Notifications appear only when the overall state *changes*, because one every
ten seconds would teach you to ignore them.

**Open logs…** serves a live page: the component panel at the top, one merged
filterable log below, streamed as it happens. It is served by the menu bar
process as you, not by the daemon — an HTTP listener cannot tell one local
caller from another, so putting one in a root service would hand every process
on the machine a window into it. The URL carries a random token for the same
reason.

**`stop` and `start`** switch everything off and on without removing anything.
Wanting the machine's own routing back for an hour is an ordinary thing to want,
and uninstalling to get it is far too much. The daemon keeps running and takes
down sing-box, the TUN, the resolver, the racer and the container, so the
machine routes its own traffic again; scoped resolvers go with them and come
back on `start`. A stop is remembered, so a reboot does not quietly turn routing
back on. Because the daemon stays up, neither needs a password.

**`reload`** validates before it applies: the sing-box document is regenerated
and checked by sing-box itself, and if it is rejected nothing is written and
nothing restarts. It then restarts only the components whose settings changed —
editing a racer timeout does not drop your tunnel.

## Configuration

`~/.config/vpnctl/config.yaml`. Run `vpnctl config-example` for the annotated
default; every value shown there is also the built-in default, so an omitted key
never changes behaviour.

```text
~/.config/vpnctl/
├── config.yaml            everything configurable
├── company.ovpn           your OpenVPN profile          (600)  written by setup
├── auth.txt               username and password         (600)  written by setup
├── .env                   TOTP_SECRET                   (600)  written by setup
├── rules/force-vpn.json   domains and apps forced through the VPN
└── run/vpn-dns            written by the container, read by the DNS router
```

The one you are most likely to touch:

```yaml
dns_router:
  bind_interface: en0     # the physical interface direct traffic binds to
```

### Forcing domains or applications through the VPN

`~/.config/vpnctl/rules/force-vpn.json` is a sing-box source rule-set, reloaded
automatically when it changes — no `vpnctl reload` needed. Use it for
destinations whose address looks public but which must never be reached
directly.

```json
{
  "version": 4,
  "rules": [
    { "domain_suffix": ["customer.example"] },
    { "process_name": ["CustomerApp"] },
    { "process_path_regex": ["^/Applications/CustomerApp\\.app/Contents/.*"] }
  ]
}
```

Keep domain and process matchers in **separate** rule objects: fields inside one
object are ANDed, separate objects match independently. Delete an unused object
entirely — `{"process_name": []}` is rejected with `missing conditions`. An
empty `"rules": []` is valid and forces nothing.

Matching is by HTTP `Host` and TLS/QUIC SNI, sniffed before the rule is applied,
because a TUN connection arrives with only a destination address. Process rules
cover TCP and UDP, so a matched application fails closed rather than falling
back to direct when the VPN is down.

### Scoped resolver domains

Naming a suffix here tells macOS to resolve it here, by way of a file in
`/etc/resolver`:

```yaml
dns_router:
  resolver_domains:
    - corp.example.com
    - domain: staging.example.com
      enabled: false
```

A bare name is on; the mapping form keeps a suffix declared but switched off.
Three equivalent ways to change it: edit the config and `vpnctl reload`, run
`vpnctl resolver off corp.example.com`, or tick the checkbox in the menu bar.

This is not about routing — while sing-box is running, its TUN already captures
every port-53 packet. What it adds is a statement that does not depend on the
tunnel: these names are answered *here*, per suffix, so an internal name is
never asked of a public resolver, not even briefly.

Two behaviours are deliberate. The files survive a *failure* — if the daemon
crashes, those names fail rather than fall back to a public resolver — but not a
*decision*: `vpnctl stop` removes them and `vpnctl start` writes them back,
because otherwise stopping would leave a suffix unable to resolve at all, even
on a network that answers it without any tunnel. And a resolver file somebody
wrote by hand for the same suffix is left alone unless it already points at the
same place, because silently redirecting where a machine sends its DNS is not a
decision this program gets to make.

## How it works

```text
macOS applications
        |
   sing-box TUN (utun225, auto_route)
        |
        +-- process is vpnctl itself --------> direct        (breaks the DNS loop)
        |
        +-- port 53 ------------------------> hijack-dns --> DNS router :15353
        |                                                      |
        |                                     public resolver <+> VPN resolver
        |                                     (bound to en0)      (via SOCKS)
        |
        +-- sniff HTTP Host, TLS/QUIC SNI     (so the next rule can match names)
        |
        +-- matches force-vpn rules --------> SOCKS :1080 --> OpenVPN tun0
        +-- LAN address --------------------> direct
        +-- private / CGNAT address --------> SOCKS :1080 --> OpenVPN tun0
        +-- any other UDP ------------------> direct
        |
        +-- any other TCP -----------------> racer :15080 -+-> direct
                                                           +-> SOCKS :1080

  vpnctl daemon (root, launchd)          the VPN container (OpenVPN + Dante)
    ├── DNS router      :15353/udp         iptables kill-switch: the proxy can
    ├── TCP racer       :15080/tcp         only leave through tun0, and is
    ├── sing-box  (child, guarded)         stopped if the tunnel drops
    └── container control (Engine API)
```

The DNS router does not tell sing-box where to route anything. It returns an
address, and sing-box's existing rules decide from the address alone. That is
why there is no per-domain routing table to maintain.

Two properties hold the rest together. **sing-box must never outlive the DNS
router and the racer**, because it installs the routes that make every
application depend on them; `vpnctl singbox-shim` blocks on a pipe whose only
writer is the daemon, so the kernel reports EOF the moment that process stops
existing — which works even for a SIGKILL, where no cleanup runs. And **health
is measured as connectivity, not liveness**: three paths are compared, and a
machine that is reachable directly but not the way an application goes means
this stack is the problem, so it is taken down rather than restarted harder.

### Security properties

- The proxy inside the container can only reach the network through `tun0`. If
  OpenVPN disconnects, it is stopped, and its traffic stays blocked.
- The SOCKS port is published on loopback only.
- Public traffic **fails open**: with the VPN down, the resolver falls back to
  public DNS and the racer falls back to direct.
- Corporate traffic **fails closed**: destinations matching the force-VPN rules,
  and private addresses, are never silently sent out directly. This is
  deliberate, not a bug to be fixed.
- The daemon refuses to execute any binary a non-root user can replace, so a
  process running as you cannot choose what root runs.
- The control socket is reachable only by the user the daemon was installed for.
- Generated one-time codes are never written to logs.

Never commit `.env`, `auth.txt`, or an OpenVPN profile. After installation they
live in `~/.config/vpnctl/`, outside this repository.

## When things go wrong

Start with `vpnctl doctor`. It checks the installation and prints a command for
anything it finds.

| What happens | Effect |
|---|---|
| VPN tunnel drops | Public traffic unaffected. Corporate DNS and private destinations fail, by design. Status goes yellow, not red. |
| Container runtime absent (before login, or not installed) | Same as above. The daemon retries and creates the container when it appears. |
| sing-box crashes | The TUN and its routes disappear with the process and the machine falls back to its own routing. The daemon restarts it with backoff. |
| sing-box crash-loops | After 5 failures in 60s the breaker stops trying and leaves the machine on native routing, because flapping the default route is worse than having no split routing. `vpnctl retry` resumes. |
| The daemon is killed, however violently | sing-box goes down with it within about a second, and the machine keeps working. |
| Applications cannot reach the network but the interface can | The daemon concludes its own stack is the problem and takes it down rather than restarting it forever. |
| Your machine is simply offline | Nothing is restarted. Churn would not help. |

```bash
vpnctl logs -f                     # everything, tagged by component
vpnctl logs -source singbox        # one component
sudo tail -f /usr/local/var/log/vpnctl/daemon.log

vpnctl check                       # validate the config and the generated document
vpnctl gen-singbox                 # print the document sing-box is given

dig @127.0.0.1 -p 15353 example.com                                    # the resolver
curl --socks5-hostname 127.0.0.1:15080 https://example.com             # the racer
curl --socks5-hostname 127.0.0.1:1080 https://internal.example.com     # the tunnel

netstat -rn -f inet | grep utun225 # the routes sing-box installed
docker logs -f vpnctl-vpn          # the container, raw
```

Repeated log lines are folded with a count, so `(x40)` means the same event
forty times rather than forty things going wrong.

If your VPN words its one-time-code challenge unusually, the prompt patterns are
in `container/context/vpn.exp`; inspect the non-secret part of the OpenVPN log
and adjust the regular expression. Never post a TOTP secret, a generated code,
an auth file, or a VPN profile anywhere.

### Where things live

```text
/usr/local/libexec/vpnctl/          vpnctl and sing-box, root-owned
/usr/local/var/vpnctl/              generated sing-box config, pid files
/usr/local/var/log/vpnctl/          daemon.log
/usr/local/etc/vpnctl/install.json  who this installation belongs to
/var/run/vpnctl.sock                control socket
/Library/LaunchDaemons/vpnctl.plist
~/Library/Logs/vpnctl-menubar.log   the menu bar's own output
```

## Development

```bash
go build ./... && go vet ./... && go test ./...
go build -o vpnctl ./cmd/vpnctl
```

CI runs on macOS, not by preference: the router binds a routing socket and the
supervisor drives launchd, so the module does not compile anywhere else.

`vpnctl run-router` runs just the resolver and the racer in the foreground,
which is convenient while working on them. `vpnctl menubar` does the same for
the menu bar. `tools/bench.sh` measures the stack against a transfer that
bypasses it, and prints the spread beside each median so a noisy sample cannot
be read as a change.

**Changing the image** means editing `container/context/` and rebuilding
`vpnctl`: the tag carries a hash of that directory, so the daemon cannot end up
running an image that does not match the binary. Then `sudo vpnctl install`.
`docker-compose.yml` is kept only for working on the image by hand and is not
used at runtime.

`TestGeneratedMatchesCommitted` compares the generated sing-box document against
`singbox/config.json`. If you change routing or DNS behaviour it will fail —
that is the point. Update the committed file in the same commit and say why.

**Releasing** is a tag; CI does the rest.

```bash
git tag -a v0.1.0 -m "…" && git push origin v0.1.0
```

The workflow builds with `-trimpath`, publishes the archive with a `SHA256SUMS`
beside it, and refuses to release a binary that still contains build paths —
dropping `-trimpath` is an easy mistake, and the result is somebody's username
in a public artefact.

## Uninstall

```bash
sudo vpnctl uninstall
```

Removes the launchd jobs, the managed binaries and the scoped resolvers. Your
config, your secrets and the container are left alone; add `-purge` to take the
container, its image and the logs as well.

## License

MIT. See [LICENSE](LICENSE).
