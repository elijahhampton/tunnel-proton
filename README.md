# tunnel-proton

A terminal UI and a privileged macOS daemon for a personal WireGuard VPN. The daemon, `vpnuid`,
drives a WireGuard tunnel from configuration files you download from your own VPN account,
and protects it with a pf-based kill switch. The terminal client, `vpnui`, is unprivileged and
holds no secrets.

> **Status.** Everything that does not need root is tested automatically (`cargo test`). Every
> part that touches pf, routes, DNS, or a real `utun` interface is **unverified until you run
> [docs/MANUAL_TEST.md](docs/MANUAL_TEST.md)**. Read [SECURITY.md](SECURITY.md) first, and keep
> `sudo vpnuid rescue` in mind: it restores a clean network without the daemon.

## Architecture

```
  your user (unprivileged)                      root
 ┌───────────────────┐   NDJSON, protocol v2   ┌──────────────────────────────────────────────┐
 │ vpnui (TUI)       │   /var/run/vpnui/       │ vpnuid run                                    │
 │ no keys, no       │──── vpnui.sock ────────▶│  server: peer-uid check, ≤ 8 clients, 1 MiB   │
 │ privileges        │   root:<your gid> 0660  │     │ commands            ▲ snapshot + events │
 └───────────────────┘                         │     ▼                     │                   │
                                               │  engine thread: the only owner of tunnel,     │
                                               │  policy, route, and DNS state                 │
                                               │     │ write-ahead journal → /var/db/vpnui/     │
                                               │     ▼                       state.json (0600) │
                                               │  Platform trait ─┬─ MacPlatform (real)        │
                                               │                  └─ FakePlatform (all tests)  │
                                               └──┬──────────┬──────────┬──────────┬───────────┘
                                                  │          │          │          │
                                    /sbin/pfctl ──┘  /sbin/route,   /usr/sbin/   pinned wireguard-go
                                    anchor            ifconfig      scutil       (/usr/local/libexec/vpnui)
                                    com.apple/000.vpnui                          UAPI: /var/run/wireguard/utunN.sock
```

```
crates/
  vpnui-proto    wire types (protocol v2), framing, golden fixtures
  vpnui-daemon   vpnuid: engine, platform layer, socket server, CLI
  vpnui-tui      vpnui: the terminal client
  vpnui-mockd    an unprivileged mock daemon for UI work and tests
```

The kill switch is a standing default-deny pf ruleset in its own anchor. The engine never reacts
to a leak; it only adds and removes narrow exceptions: UDP to the current server's endpoint,
and traffic on the exact `utun` interface of the live tunnel. Each exception exists exactly while
its write-ahead journal entry exists, so a crash leaves the system blocked, and the next start
undoes whatever the journal lists.

## Install

Requirements: macOS on Apple silicon or Intel, the Rust toolchain, and `wireguard-go`
(`brew install wireguard-go`). The `wg` tool is not needed; vpnuid speaks WireGuard's UAPI
directly so keys never appear on a command line.

```sh
cargo build --release
sudo ./target/release/vpnuid install --dry-run           # prints every file and command
sudo ./target/release/vpnuid install --yes               # copies, pins, and starts the service
```

`install` copies `wireguard-go` and `vpnuid` into `/usr/local/libexec/vpnui/` (root:wheel, 0755),
prints and records their SHA-256 hashes in `/var/db/vpnui/install.json`, writes the LaunchDaemon
`/Library/LaunchDaemons/dev.vpnui.daemon.plist`, and records which user may control the daemon
(`--user NAME`, default: the user who ran sudo). The daemon re-verifies each pinned binary's
hash and the ownership of every parent directory before each launch of wireguard-go.

For a first run without installing the service, see step 2 of the manual test.

## Getting configs and importing them

Your VPN provider's account website has a WireGuard configuration page where you can generate
and download one `.conf` file per server. That page is the only input vpnui supports; it never
talks to the provider. Download a few servers, for example one in Colombia, then:

```sh
sudo vpnuid import ~/Downloads/CO-4.conf ~/Downloads/US-NY-123.conf
sudo vpnuid list            # grouped by country
```

- Each file is validated strictly. Configs containing `PreUp`, `PostUp`, `PreDown`, `PostDown`,
  `SaveConfig`, `Table`, or `FwMark` are rejected: they would let a file run commands as root.
  Endpoints must be literal IPv4 addresses; hostnames are rejected.
- The display name comes from a comment in the `[Peer]` section (for example `# CO#4`), else the
  file name. The country comes from a leading ISO code such as `CO#4` or `US-NY#123`. Override
  with `--name`, `--country`, and `--city`.
- Profiles are stored as normalized JSON in `/var/db/vpnui/profiles/` (root, 0700; files 0600).
  Re-importing the same server updates it in place and keeps its id.
- **The source file still contains your private key.** Import prints a reminder; delete the file
  yourself or pass `--delete-source`.

Only countries you import appear in the client. There is no server list, load, or latency data:
those fields show as `—`.

## Daily use

```sh
vpnui                  # the TUI, talking to /var/run/vpnui/vpnui.sock
vpnuid status          # one-shot state from the running daemon
sudo vpnuid doctor     # diagnostics and a pf self-test
sudo vpnuid rescue     # restore a clean network without the daemon
```

In the TUI: `c` quick connect (your most recent server, else the newest import; the footer names
it), `Enter` on a server connects, `d` disconnects, `s` arms or disarms the kill switch, `?` lists
every key. The posture card always says one of PROTECTED, EXPOSED, BLOCKED, or UNKNOWN.

| tunnel \ kill switch | `off`     | `armed`   | `error`   |
|----------------------|-----------|-----------|-----------|
| `disconnected`       | EXPOSED   | BLOCKED   | EXPOSED   |
| `connecting`         | EXPOSED   | BLOCKED   | EXPOSED   |
| `connected`          | PROTECTED | PROTECTED | PROTECTED |
| `reconnecting`       | EXPOSED   | BLOCKED   | EXPOSED   |
| `disconnecting`      | EXPOSED   | BLOCKED   | EXPOSED   |

If the daemon is unreachable the posture is UNKNOWN and last-known data is shown dimmed as stale.

### Working on the UI without root

```sh
cargo run -p vpnui-mockd -- --scenario flaky
cargo run -p vpnui-tui -- --socket "$TMPDIR/vpnui.sock"
```

## Daemon commands

```
vpnuid run [--socket PATH] [--wireguard-go PATH] [--auto-rescue-after SECS] [--ip-check-url URL]
vpnuid import [--name N] [--country CC] [--city C] [--delete-source] FILE...
vpnuid list [--json]          vpnuid remove ID
vpnuid status [--json]
vpnuid install [--user NAME] [--wireguard-go PATH] [--yes] [--dry-run]
vpnuid uninstall [--dry-run]
vpnuid doctor                 vpnuid rescue
```

- `run` needs root. `--wireguard-go` is accepted only for a root-owned file in root-owned,
  non-writable directories. `--auto-rescue-after 300` makes the daemon run a full rescue and
  exit after five minutes, unconditionally, which is the safe way to try it for the first time.
- `--ip-check-url https://...` enables one HTTPS GET (run as `nobody`, 5 s timeout) each time the
  tunnel connects, expecting a plain-text IP. It is off by default; without it the client shows
  "IP: not checked" and the server's entry address.
- `list` and `status` work without root when the daemon is running; `list` reads the store
  directly as root.

## Protocol v2

Unix socket, newline-delimited JSON, at most 1 MiB per line, versioned by `hello`. v2 is
additive over v1; unknown fields are ignored and unknown enum values decode to `unknown`.

Changes from v1:

- `protocol_version` is 2.
- `Server`: `load_pct`, `latency_ms`, `lat`, `lon` are optional (null when unknown). New optional
  `profile_id`, `entry_ip` (the endpoint address, display only), and `imported_at_ms`.
- `IpInfo`: `lat`/`lon` optional, `city`/`country` may be empty.
- `snapshot.profiles_count`.
- Command `reload_profiles`; `servers_updated` follows import, remove, and reload.
- Error codes: `no_profiles`, `unknown_server`, `no_network`, `binary_untrusted`,
  `handshake_timeout`, `pf_failed`, `route_failed`, `dns_failed`, `wg_failed`, `busy`,
  `unauthorized`, plus v1's `bad_request`, `invalid_state`, `version_mismatch`, `internal`.
- A refused connection receives one line, `{"id":0,"ok":false,"error":{"code":"unauthorized"|"busy",...}}`,
  and is closed.
- `tunnel.disconnected.last_error` from vpnuid has the form `"<code>: <detail>"`.

Units, unchanged from v1:

- `stats.rx_bytes` and `stats.tx_bytes` are cumulative bytes for the current wireguard-go
  instance; they restart from zero after a reconnect that replaces the instance.
- `stats.last_handshake_ms`, `connected.since_ms`, `connecting.started_at_ms`, and
  `reconnecting.retry_at_ms` are milliseconds since the Unix epoch.
- `stats` is sent once a second while connected.

Example:

```
→ {"id":1,"cmd":{"type":"hello","client_version":"0.1.0","protocol_version":2}}
← {"id":1,"ok":true,"protocol_version":2}
→ {"id":2,"cmd":{"type":"subscribe"}}
← {"id":2,"ok":true}
← {"event":{"type":"snapshot","protocol_version":2,"tunnel":{"type":"disconnected","last_error":null},
   "kill_switch":{"type":"armed"},"settings":{...},"servers":[{"id":"co-4-1a2b3c","name":"CO#4",
   "country_code":"CO","country":"Colombia","city":"","lat":4.57,"lon":-74.3,"load_pct":null,
   "latency_ms":null,"features":[],"profile_id":"co-4-1a2b3c","entry_ip":"203.0.113.40",
   "imported_at_ms":1760000000000}],"recents":[],"public_ip":null,"profiles_count":1}}
→ {"id":3,"cmd":{"type":"connect","server_id":"co-4-1a2b3c"}}
← {"id":3,"ok":true}
← {"event":{"type":"tunnel_changed","tunnel":{"type":"connecting","server_id":"co-4-1a2b3c","phase":"resolving",...}}}
← {"event":{"type":"tunnel_changed","tunnel":{"type":"connecting","server_id":"co-4-1a2b3c","phase":"handshaking",...}}}
← {"event":{"type":"tunnel_changed","tunnel":{"type":"connected","server_id":"co-4-1a2b3c",
   "since_ms":1760000002017,"endpoint":"203.0.113.40:51820","last_handshake_ms":1760000002017}}}
```

Golden fixtures live in `crates/vpnui-proto/tests/fixtures/`.

## Troubleshooting

- **No network at all.** Run `sudo vpnuid rescue`. It stops the service and wireguard-go, removes
  journaled routes and the DNS override, flushes the kill-switch anchor, releases the pf token,
  and marks the kill switch disarmed. If `vpnuid` itself is unavailable, see the emergency
  section of [docs/MANUAL_TEST.md](docs/MANUAL_TEST.md).
- **`binary_untrusted`.** wireguard-go is not pinned, its hash changed (for example after
  `brew upgrade`), or a parent directory is writable. Rerun `sudo vpnuid install`.
- **`install` refuses `/usr/local/libexec`.** On Intel Macs with Homebrew in `/usr/local`, some
  of those directories belong to your user, so binaries there cannot be trusted as root. Make
  `/usr/local/libexec` root-owned or move Homebrew.
- **`handshake_timeout`.** The server did not respond within 15 s: check the config is current
  and that the network allows UDP to the endpoint port.
- **`unauthorized` in the TUI.** Only root and the user recorded by `install --user` (or the
  user who ran `sudo vpnuid run`) may use the socket.
- **Kill switch shows ERROR.** pf rejected the policy or could not be enabled. `sudo vpnuid
  doctor` checks whether pf evaluates the anchor on this macOS version.
- Logs: `/var/log/vpnui/vpnuid.log` for the service, stderr for `vpnuid run`.

## Known limitations

- **Boot window.** pf rules live in kernel memory and are gone after a reboot. Between the
  network coming up and launchd starting vpnuid (which loads the policy before anything else
  when the kill switch was armed), traffic can leave unprotected. Possible mitigations, none of
  them implemented: adding the anchor to `/etc/pf.conf` with a block-all default (OS updates may
  revert it, and a mistake there breaks networking for every user); a `pf.conf`-loaded block
  that a later daemon replaces; or moving to a Network Extension. This window is not closed.
- No IPv6 endpoints; one peer per profile. IPv6 traffic is routed into the tunnel (`::/1`,
  `8000::/1`), so it either goes through it or is discarded.
- DNS queries scoped to a specific interface, and domains with a more specific resolver (such
  as `/etc/resolver/*` or another VPN's split domains), bypass the override.
- Any process running as your user can use the socket, including disarming the kill switch.
- Network changes are detected by polling once a second; recovery can lag by that much.

## Development

```sh
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
VPNUID_RANDOM_RUNS=20000 cargo test -p vpnui-daemon --lib randomized   # longer soak
VPNUID_RANDOM_SEED=65 cargo test -p vpnui-daemon --lib randomized      # replay one seed
```

`unsafe` is forbidden; `unwrap`/`expect` are denied outside tests; matches on state enums may not
use wildcards. Judgment calls are in [DECISIONS.md](DECISIONS.md).
