# vpnctl

Split routing for macOS: corporate traffic through an OpenVPN tunnel, everything
else straight out of the physical interface, decided per destination rather than
per application.

One binary supervises the whole thing. One configuration file describes it.

```bash
sudo vpnctl install     # once
vpnctl status           # any time, no password
```

## What it does

Some destinations are only reachable from inside a VPN. Most are not. Routing
everything through the tunnel is slow and leaks personal traffic through a
corporate gateway; routing nothing through it means the VPN is useless. So the
decision has to be made per destination, and it has to be made without asking
anyone to maintain a list.

Two mechanisms do that. Every DNS lookup is resolved twice in parallel — once
against a public resolver and once against the DNS servers the VPN pushed — and
a private-IP answer from the corporate side wins, which makes the destination
route itself. For destinations whose address looks public but is only reachable
from inside the tunnel, both paths are dialled at once and the first to connect
wins, remembered per destination.

## Architecture

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

## Security properties

- The proxy inside the container can only reach the network through `tun0`. If
  OpenVPN disconnects, it is stopped, and its traffic stays blocked.
- The SOCKS port is published on loopback only.
- Public traffic **fails open**: with the VPN down, the resolver falls back to
  public DNS and the racer falls back to direct.
- Corporate traffic **fails closed**: destinations matching the force-VPN rules,
  and private addresses, are never silently sent out directly. This is
  deliberate and is not a bug to be "fixed".
- The daemon refuses to execute any binary a non-root user can replace, so a
  process running as you cannot choose what root runs.
- The control socket is reachable only by the user the daemon was installed for.
- Generated one-time codes are never written to logs.

Never commit `.env`, `auth.txt`, or an OpenVPN profile. After installation they
live in `~/.config/vpnctl/`, outside this repository.

## Requirements

- macOS on Apple silicon or Intel
- A container runtime with `/dev/net/tun`: OrbStack, Docker Desktop, or colima.
  It is **not** installed for you, and it runs in your login session, so the VPN
  is unavailable until you log in. Public traffic works regardless.
- Go 1.26 or newer to build `vpnctl`
- An OpenVPN profile, its credentials, and the Base32 TOTP secret for its
  one-time-code challenge

sing-box is installed for you.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/nhatphat/vpn-router/main/install.sh | sh
```

That downloads the latest release, checks it against the checksum published
beside it, and runs `vpnctl install`. It will ask for your password once, at
that last step. The script is short and worth reading before you pipe it to a
shell.

Only Apple silicon is published. On an Intel Mac, or to run your own build:

```bash
go build -trimpath -o vpnctl ./cmd/vpnctl
sudo ./vpnctl install
```

`-trimpath` is not optional for anything you hand to someone else: without it Go
records the absolute path of every source file in the binary, which on a normal
machine puts your username in it a hundred times over.

Later, `sudo vpnctl update` fetches the newest release, verifies it, and hands
over to its own installer — so an upgrade takes the same path a fresh install
does, including a changed sing-box version or container definition.
`vpnctl update -check` only looks.

`install` asks for authorisation once, through `sudo` — which means a fingerprint
if you have `pam_tid.so` in `/etc/pam.d/sudo_local`, and a password otherwise. It
then:

1. copies itself to `/usr/local/libexec/vpnctl/` and links `/usr/local/bin/vpnctl`
2. installs a **root-owned** copy of sing-box, downloading the published
   release and verifying it against the checksum pinned in `singbox.sha256`,
   which ships pinned per platform. `-from-path` copies the one already on
   your `PATH` instead — faster, and it reuses whatever verification your
   package manager did, but the pin does not apply to it because a
   distribution's build is a different binary. Homebrew's, for instance,
   hashes differently because it builds from source.
3. writes `~/.config/vpnctl/config.yaml` if you have none
4. builds the VPN image from a build context embedded in the binary, and creates
   the container
5. installs a LaunchDaemon and starts it

Nothing after that needs a password. The daemon is resident, so it comes back
after a reboot before anyone logs in, and restarts from the CLI are immediate.

Then point it at your VPN:

```bash
vpnctl setup
```

It asks for the path to your `.ovpn` profile, your username and password, and
the Base32 TOTP secret — then writes all three into `~/.config/vpnctl/` with
the right permissions and recreates the container with them. No `sudo`: these
are your credentials, in your directory.

The secret is checked while you type it. `setup` generates the code that secret
produces right now and asks whether it matches your authenticator, because a
mistyped secret is otherwise indistinguishable from a wrong password or a
server problem, and only surfaces as a VPN that will not connect.

```
  That secret produces 287082 right now, valid for 16 more seconds.
  Does that match your authenticator? [Y/n]:
```

`vpnctl doctor` when it finishes.

### Coming from the older manual setup

If you were running `host-dns-router` and `sing-box` by hand out of a checkout:

```bash
sudo vpnctl migrate /path/to/vpn-router
sudo vpnctl install
```

`migrate` copies the profile, the auth file, `.env` and the force-VPN rules into
`~/.config/vpnctl/` and repoints the config at them. It **copies**; your
originals are left alone. After this the installation reads nothing from the
checkout — `vpnctl doctor` verifies that under `independence`.

## Everyday use

| Command | What it does |
|---|---|
| `vpnctl status` | what every component is doing; `-w` to follow |
| `vpnctl logs` | one merged, tagged log; `-f` to follow, `-source vpn\|singbox\|dns\|racer\|supervisor` |
| `vpnctl setup` | point it at a `.ovpn` profile and your credentials |
| `vpnctl doctor` | check the installation and print the fix for anything wrong |
| `sudo vpnctl update` | install the newest release; `-check` only reports |
| `vpnctl reload` | apply an edited config, restarting only what changed |
| `vpnctl resolver [on\|off <domain>]` | list scoped resolver domains, or switch one |
| `vpnctl restart <component>` | `vpn`, `singbox`, `dns-router`, `racer`, or `all` |
| `vpnctl retry` | leave safe mode after the breaker gave up on sing-box |

None of these need `sudo`.

There is also a menu bar item, installed by default and started at login. It
shows the same status, restarts any component, applies an edited config, and
opens the log page. Its **Quit menu bar** does exactly that and nothing else:
the daemon and the tunnel keep running, which is why the item is not called
"Quit". Quitting it is meant to stick, so bring it back with `vpnctl menubar
-start` or by logging in again.

Notifications appear only when the overall state *changes* — down, degraded,
recovered — because one every ten seconds would teach you to ignore them.

`reload` validates before it applies: the sing-box document is regenerated and
checked by sing-box itself, and if it is rejected nothing is written and nothing
restarts. It then restarts only the components whose settings changed — editing
a racer timeout does not drop your tunnel. Only a change that reaches sing-box
is disruptive, and `reload` says so when it is.

## The log page

**Open logs…** in the menu bar serves a live page: the component panel at the
top, and one merged, filterable log below it, streamed over server-sent events.
Filter by component or by text, pause the follow, and folded lines show their
count rather than repeating.

It is served by the menu bar process, as you, and not by the daemon. An HTTP
listener has no way to tell one local caller from another, so putting one in a
root service would hand every process on the machine a window into it. Run as
you, the page can only show what you could already read through the control
socket. The URL carries a random token as well, because a loopback listener is
still reachable by every local process, including other users'.

The listener starts when you first open the page and not before.

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

The two you are likely to touch:

```yaml
dns_router:
  bind_interface: en0     # the physical interface direct traffic binds to

singbox:
  tun:
    stack: gvisor         # gvisor | system — see below before changing
```

### Forcing domains or applications through the VPN

`~/.config/vpnctl/rules/force-vpn.json` is a sing-box source rule-set, reloaded
automatically when it changes — no `vpnctl reload` needed.

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
entirely — `{"process_name": []}` is rejected with `missing conditions`. An empty
`"rules": []` is valid and forces nothing.

Matching is by HTTP `Host` and TLS/QUIC SNI, sniffed before the rule is applied,
because a TUN connection arrives with only a destination address. Process rules
cover TCP and UDP, so a matched application fails closed rather than falling back
to direct when the VPN is down.

### About `stack: system`

`gvisor` is a userspace network stack and `system` uses the host's. `system` is
usually described as faster, and it has broken networking on the machine this
was developed on. It is a knob so you can measure it, not a recommendation —
and on the evidence below there is nothing here worth taking that risk for.

## What the stack costs

Measured against the same transfer bypassing it entirely, same destination,
samples interleaved so a change in the network hurts both equally:

| | direct | through the stack |
|---|---|---|
| download, 20MB × 5 | 25.15 MB/s | 26.28 MB/s |
| connection setup, 1KB × 15 | 157 ms | 163 ms |

Throughput is indistinguishable, and a new connection costs about 6ms more.
Both userspace hops — sing-box's network stack and the racer's relay — are in
that 6ms. There is no throughput case for changing the data path.

`tcp connect` measured through the TUN looks *faster* than direct, and that is
not a speed-up: sing-box completes the handshake locally before any real
connection exists, so the cost moves into the TLS handshake instead. It is the
behaviour the racer depends on — see the comment at the top of
`internal/racer` — and it means `time_connect` means nothing here.

This was worth measuring for a reason. Before the launchd job's `ProcessType`
was corrected, the same comparison read 0.91 MB/s against 23.14 — the stack
looked like it cost 96% of the machine's throughput, and the obvious suspects
were the network stack and the double relay. Neither was involved.

## Failure behaviour

| What happens | Effect |
|---|---|
| VPN tunnel drops | Public traffic unaffected. Corporate DNS and private destinations fail, by design. Status goes yellow, not red. |
| Container runtime absent (before login, or not installed) | Same as above. The daemon retries and creates the container when it appears. |
| sing-box crashes | The TUN and its routes disappear with the process, and the machine falls back to its own routing. The daemon restarts it with backoff. |
| sing-box crash-loops | After 5 failures in 60s the breaker stops trying and leaves the machine on native routing, because flapping the default route is worse than having no split routing. `vpnctl retry` resumes. |
| The daemon is killed, however violently | sing-box goes down with it within about a second, and the machine keeps working. See below. |
| Applications cannot reach the network but the interface can | The daemon concludes its own stack is the problem and takes it down rather than restarting it forever. |
| Your machine is simply offline | Nothing is restarted. Churn would not help. |

## How the pieces hold together

Three properties are worth understanding before changing anything.

**sing-box must never outlive the DNS router and the racer.** It installs the
routes that make every application depend on them, so a supervisor that died
while sing-box kept running would leave the machine with routes pointing at a
resolver and a proxy that no longer answer — every lookup and every connection
failing, with the interface still up. Signals cannot solve this, because a
SIGKILLed process runs no cleanup. A pipe can: `vpnctl singbox-shim` blocks
reading a descriptor whose only writer is the daemon, so the kernel reports EOF
the instant that process stops existing, and the shim stops sing-box.

**Health is measured as connectivity, not liveness.** Every component can be
running while the machine is unusable, so three paths are compared: bound to the
physical interface, through our own listeners on loopback, and an ordinary
connection that follows the default route into the TUN. Only the last covers
sing-box. Reachable directly but not the way an application goes means this stack
is the problem, and the response is to shut it down, not to restart it harder.

**The first route rule is load-bearing.** `process_name: [vpnctl]` routed direct,
ahead of `hijack-dns`, is what stops the DNS router's own queries from being
recaptured by the TUN and looping forever. A second layer binds those queries to
the physical interface. Remove either and DNS stops working in a way that looks
like a DNS problem.

## Debugging

```bash
vpnctl doctor                      # start here
vpnctl logs -f                     # everything, tagged by component
vpnctl logs -source singbox        # one component
sudo tail -f /usr/local/var/log/vpnctl/daemon.log

vpnctl check                       # validate the config and the generated document
vpnctl gen-singbox                 # print the document sing-box is given

dig @127.0.0.1 -p 15353 example.com                                   # the resolver
curl --socks5-hostname 127.0.0.1:15080 https://example.com             # the racer
curl --socks5-hostname 127.0.0.1:1080 https://internal.example.com     # the tunnel

netstat -rn -f inet | grep utun225 # the routes sing-box installed
docker logs -f vpnctl-vpn          # the container, raw
```

Repeated log lines are folded with a count, so `(x40)` means the same event
forty times rather than forty things going wrong.

### Where things live

```text
/usr/local/libexec/vpnctl/          vpnctl and sing-box, root-owned
/usr/local/var/vpnctl/              generated sing-box config, pid files
/usr/local/var/log/vpnctl/          daemon.log
/usr/local/etc/vpnctl/install.json  who this installation belongs to
/var/run/vpnctl.sock                control socket
/Library/LaunchDaemons/vpnctl.plist
```

## Development

```bash
go build ./... && go vet ./... && go test ./...
go build -o vpnctl ./cmd/vpnctl
```

```text
cmd/vpnctl/          the CLI, one file per group of subcommands
container/context/   the VPN image's build context, embedded in the binary
internal/
  config/            the YAML file, its defaults, and the executable-safety rule
  dnsrouter/         split-horizon DNS
  racer/             direct-vs-VPN TCP race
  netmon/            the bind address, tracked through the routing socket
  singbox/           config generation, the guard shim, process supervision
  dockerctl/         a minimal Engine API client
  vpnbox/            the image and the container specification
  vpndns/            the VPN-pushed DNS servers
  logbus/            merged, tagged, de-duplicated logs
  health/            the three-way connectivity probe
  status/            the vocabulary the daemon and the UI share
  ipc/               the control socket protocol
  ui/menubar/        the menu bar, and its drawn status icons
  ui/web/            the live status and log page
  supervisor/        orchestration, self-healing, reload
  installer/         launchd, managed binaries, migration
  doctor/            the checks and their fixes
```

`docker-compose.yml` is kept only for working on the image by hand. It is not
used at runtime.

`vpnctl run-router` runs just the resolver and the racer in the foreground,
which is convenient while working on them. `vpnctl menubar` does the same for
the menu bar; run it from a terminal and its state transitions go to stderr.

**Changing the image** means editing `container/context/` and rebuilding
`vpnctl`: the tag carries a hash of that directory, so the daemon cannot end up
running an image that does not match the binary. Then `sudo vpnctl install`.

### Releasing

Push a tag and CI does the rest:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

The workflow builds with `-trimpath`, publishes the archive with a `SHA256SUMS`
beside it, and refuses to release a binary that still contains build paths —
because dropping `-trimpath` is an easy mistake and the result is somebody's
username in a public artefact.

CI runs on macOS, not by preference: the router binds a routing socket and the
supervisor drives launchd, so the module does not compile anywhere else.

`TestGeneratedMatchesCommitted` compares the generated sing-box document against
`singbox/config.json`. If you change routing or DNS behaviour it will fail —
that is the point. Update the committed file in the same commit and say why.

### Platform behaviour worth knowing

Verified on macOS 26 with OrbStack, and each one cost some time:

- A container runtime only bind-mounts host paths its virtual machine shares. A
  mount of a path under `/usr/local` **silently** resolves inside the runtime's
  own VM: the container writes the file, the host never sees it, and nothing
  reports an error. Shared paths live under `/Users`.
- `docker compose` is a CLI plugin found through the invoking user's
  `DOCKER_CONFIG`, so a root daemon cannot see it at all. `vpnctl` uses the
  Engine API and never shells out to `docker`.
- A `utun` interface belongs to the file descriptor that created it, so the
  kernel destroys it — and the routes pointing at it — when the process dies.
  Orphaned routes are not a failure mode here.
- sing-box's `strict_route` does not use `pf` on macOS, and `auto_route` does not
  touch `scutil` DNS. There is no firewall or resolver state to clean up.
- A LaunchDaemon runs with no `HOME`, no `USER`, and `PATH=/usr/bin:/bin:/usr/sbin:/sbin`.
- TCC does not block a LaunchDaemon from reading `~/Downloads`.

## Scoped resolvers

Naming a suffix here tells macOS to resolve it here, by way of a file in
`/etc/resolver`:

```yaml
dns_router:
  resolver_domains:
    - corp.example.com
    - domain: staging.example.com
      enabled: false
```

A bare name is on. Write the mapping form to keep a suffix declared but
switched off. Three ways to change it, all equivalent: edit the file and
`vpnctl reload`, run `vpnctl resolver off corp.example.com`, or tick the
checkbox in the menu bar. `vpnctl doctor` reports the result, and `scutil --dns`
shows the system's own view.

Off removes the resolver file rather than marking it inactive, because while
the file exists the system resolver sends those names here — so anything less
would make "off" untrue.

The menu bar edits the config file itself and then asks the daemon to reload.
Only that one block is rewritten, line by line, so the comments in your config
survive a graphical toggle. What the menu shows is intent *and* effect
separately: a suffix can be on with no file installed, or off with a file
someone else wrote still in place, and a tick alone would imply those never
disagree.

While sing-box is running its TUN already captures every port-53 packet, so
this is not about routing. What it adds is a statement that does not depend on
the tunnel: these names are answered *here*, per suffix, so an internal name is
never asked of a public resolver — not even briefly, and not if something
bypasses the TUN.

Two consequences are deliberate. The files outlive the daemon: with nothing
listening, those names fail rather than fall back to a public resolver, which is
the same fail-closed choice this project makes for corporate traffic.
`vpnctl uninstall` removes them, and so does deleting the line and reloading.
And a resolver file somebody wrote by hand for the same suffix is left alone
unless it already points at the same place — silently redirecting where a
machine sends its DNS is not a decision this program gets to make. `vpnctl
doctor` reports either case.

## OTP prompt compatibility

`container/context/vpn.exp` recognises common challenge strings: OTP,
verification code, one-time password, token, and challenge prompts containing
OTP/token/code. If your provider words it differently, inspect the non-secret
part of the OpenVPN log and adjust the regular expression.

Never post a TOTP secret, a generated code, an auth file, or a VPN profile
anywhere.

## Uninstall

```bash
sudo vpnctl uninstall
```

Removes the launchd job and the managed binaries. Your config, your secrets and
the container are left alone.

## License

MIT. See [LICENSE](LICENSE).
