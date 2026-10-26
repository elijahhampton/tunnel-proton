# Decisions

Judgment calls made where the spec was silent or ambiguous.

## Protocol

- **Timestamps are wall-clock Unix milliseconds** (`UnixMillis`), set by the daemon. The client
  computes ages and countdowns against its own clock; both run on the same host. `stats.last_handshake_ms`
  is a timestamp like the others, not an age.
- **`hello` replies carry `protocol_version`** as an extra field on the response, the only
  response that has one. On a mismatch the mock daemon replies `ok:false` with code
  `version_mismatch` and still includes its version so the client can name both. The client
  also re-checks `snapshot.protocol_version`.
- **`hello` is not enforced** by the mock: commands sent before it are accepted. The client always
  sends `hello` and then `subscribe`.
- **`subscribe` replies `ok` first, then the snapshot.** A second `subscribe` replaces the
  subscription and sends a new snapshot.
- **Idempotent commands confirm with an event.** Connecting to the current server, disconnecting
  while disconnected, or setting the kill switch to its current value succeeds and re-broadcasts
  the current state, so the requester's pending indicator always resolves.
- **No `recents_changed` event.** The documented rule (move to front on connect) lets clients
  maintain recents from `tunnel_changed`; the snapshot is authoritative. The mock keeps 8; the
  client shows 5.
- **Public IP semantics.** `public_ip` is the address traffic would leave from: the real address
  while the tunnel is down (including while blocked) and the exit address while connected.
- **Throughput** is derived from consecutive cumulative `stats` events, assuming the documented
  1 Hz cadence. A counter that goes backwards resets the history.
- **Oversized lines close the connection.** tokio-util's `FramedRead` ends the stream after a
  decode error, so both sides treat a line over 1 MiB as fatal for that connection.
- **Malformed requests**: if a usable `id` can be salvaged the mock replies `bad_request`;
  otherwise it logs and drops the line. Unknown command types get `bad_request`.
- **Lagging subscribers** (broadcast buffer overrun) get a fresh snapshot instead of being cut
  off.
- **Unknown variants.** `tunnel_changed` or `kill_switch_changed` carrying an unknown state is
  logged and skipped. An unknown state inside a snapshot is stored; `posture()` treats an
  unknown tunnel as not connected and an unknown kill switch as not blocking. Unknown features
  are hidden. Unknown event types are logged and skipped.

## Client state

- **Time advances only on `Tick` events**, so `update` stays pure and deterministic in tests.
  Pending timeouts and toast expiry therefore have tick granularity (up to 1 s while idle).
- **`DaemonLink::Live` means a snapshot has arrived on the current socket.** `Connecting` covers
  both opening the socket and the hello/subscribe handshake. `Lost.since` keeps the original
  loss time across failed retries, and is stored as an instant (`next_retry_at`) so the
  countdown renders from state.
- **The projection is discarded the moment a new socket opens**, not when the snapshot arrives;
  stale data is shown only while the link is `Lost`. On stale screens, uptime, elapsed time, and
  handshake age freeze at the moment the link was lost, and action hints are hidden.
- **Link backoff resets after a successful connect**, so the first retry after a drop waits 1 s.
- **In-flight requests are dropped on any link reset**, with a toast if any were user actions.
- **What confirms a request**: `connect` is settled by `tunnel_changed` to `connecting` or
  `connected` on that server (not `reconnecting`, which can be a stale echo); `quick_connect` by
  any `connecting`/`connected`; `disconnect` by `disconnecting`/`disconnected`;
  `set_kill_switch` by any `kill_switch_changed`, including `error`, which is reported as a
  failure; settings by `settings_changed` showing the requested value. An `ok` response marks
  the request acknowledged but does not clear `pending…`.
- **Dedupe slots**: all tunnel actions share one slot; the kill switch has one; each setting has
  its own. A press while the slot is busy is refused with a footer message.
- **Origin marker.** The client remembers the last public IP seen while disconnected as the
  user's location. If it has only ever seen a connected state, the "you" marker is hidden rather
  than drawn at the exit server.

## Confirmations

- **Disconnect asks only when connected with the kill switch armed**, the case where posture
  drops from PROTECTED to BLOCKED. Cancelling a connect or reconnect while armed goes straight
  through, since posture is already BLOCKED and stays there. Disconnecting with the kill switch
  off is not confirmed: it is the explicit primary action and involves no kill-switch decision.
- **"Lowers protection"** means disarming, turning LAN access on, and turning IPv6 blocking off.
  Turning auto-reconnect off is applied directly.
- **Kill switch in `error`**: `s` opens a dialog with *Retry arming*, *Turn kill switch off*,
  and *Cancel*.
- **Dialogs default to Cancel** and list options vertically so they fit at 60 columns.

## Interaction

- On Home, `j`/`k` and `Enter` act on the recents list. In the narrow layout the recents panel
  moves into the Home view. Clicking a recent in the rail switches to Home so `Enter` targets it.
- `Esc` priority: close dialog, then leave search typing, then clear an active search, then
  cancel an in-progress connect.
- While typing a search, `q` is a character; `Ctrl-C` always quits.
- `r` while disconnected reconnects to the most recent server. `c` works while disconnected or
  reconnecting.
- Clicking the rail's kill-switch row behaves like `s`, confirmations included. The mouse wheel
  moves list selections by three and scrolls the help overlay.
- Unavailable-action messages are toasts, so they also land in the event log.
- The event log records tunnel transitions, kill-switch and settings changes, link changes,
  daemon `log` events, and every toast. `stats` and `servers_updated` are not logged.
- One toast at a time; the newest replaces the previous.

## Layout and rendering

- **Wide** is at least 100x30. Everything else from 60x18 up is **narrow**, including wide
  terminals shorter than 30 rows.
- The Servers view gives the tree 60% of the width. Feature tags render as aligned short
  columns (`p2p str mh`); the detail pane and help overlay spell them out.
- The tree always shows the city level, even for single-city countries. Name sort orders
  servers by id, which is zero-padded and so numerically ordered. Load sort orders groups by
  average load; latency sort orders groups by their fastest server.
- Search matches country, city, and server name (not codes or ids), and auto-expands matching
  groups.
- The posture banner is a 3-row solid block (posture color as background, reverse video
  without color).
- The map crops latitudes below -60 (Antarctica) to use the rows for land. The route line is
  drawn only while connecting or connected. The server marker is the tunnel's server, else the
  tree selection.
- The sparkline is right-aligned so the newest sample is always at the right edge.
- Redraws happen after each drained batch of events and on ticks. Mouse move and drag events
  are filtered out before they reach the reducer.

## Theme

- `NO_COLOR` with any non-empty value disables color. `COLORTERM=truecolor|24bit` selects
  truecolor; anything else gets the 16-color palette. `--color` overrides detection.
- Monochrome distinguishes roles with bold, reverse, dim, and underline.
- `--ascii` replaces borders (`+-|`), bars (`#.`), symbols (`+ x # ?`), the spinner, and the
  map marker (`Marker::Custom('.')`). Data from the daemon, such as `Zürich`, is not
  transliterated.
- The warning glyph is `!`, not U+26A0, which some terminals render as a double-width emoji.

## Mock daemon

- 24 countries, 41 cities, 2-7 servers per city (about 180). Latency is estimated from
  great-circle distance to New York (about 80 km per ms of RTT) plus jitter. Exit IPs are
  `198.51.100.1`-`.254`, so the catalog is capped at 254 servers.
- Server names are `City #N`; ids are `cc-city-NNN`.
- Loads random-walk by up to ±4 points every 5 s; latency jitters around each server's base.
- Reconnect attempts stay in `reconnecting` (`retry_at_ms` null while attempting) rather than
  re-entering `connecting`. The attempt counter increments and the original reason is kept.
  Attempts fail 10% of the time in `calm`, 35% in `flaky`.
- Settings apply after about 200 ms; a second patch while one is pending merges into it. An
  empty patch is `bad_request`.
- `ks-error` forces `error` regardless of the current state and makes arming fail until
  `ks-clear`, which re-applies the policy if the kill switch is in `error`.
- `crash` calls `process::exit(101)`, leaving the socket file behind. In-process tests simulate
  a crash by aborting the `serve` future, which owns the state task and every client task.
- `Config::time_scale` multiplies every simulated delay, and `without_random_faults()` disables
  random handshake failures, so integration tests run fast and deterministically.
- The socket gets mode 0600 immediately after `bind`. There is a brief window before the
  `chmod`; the default path is inside the per-user `$TMPDIR`, which macOS creates as 0700. A
  real daemon should create its socket inside a directory it controls.
- A non-socket file at the socket path is never removed.

## Process and logging

- The exit line is printed on normal exit, error exit, and signal-triggered exit. The panic hook
  restores the terminal, prints the report and the exit line, and exits with status 101 so a
  panic on any thread cannot leave the screen in raw mode.
- Logs: `~/Library/Logs/vpnui/vpnui.log` on macOS, `$XDG_STATE_HOME/vpnui/vpnui.log` (or
  `~/.local/state/vpnui/`) elsewhere; `--log-file` overrides; `RUST_LOG` filters.

## Tooling

- Edition 2024, resolver 3, Rust 1.94.
- `clippy::wildcard_enum_match_arm` is denied workspace-wide, which is stricter than "state
  enums only". It is allowed, with a reason, on the four functions that match crossterm's
  open-ended `KeyCode`. Matches on integers keep their `_` arms.
- `clippy.toml` allows `unwrap`/`expect` inside `#[cfg(test)]`; integration test files allow
  them at the top of the file.
- No dependencies beyond the expected list. `pretty_assertions` and `bytes` were considered and
  dropped.

---

# v2: the real daemon

## Where the code differed from the spec's assumptions

- The v1 code had no `Event` size problem; v2's larger `Server` made `DaemonMessage` trip
  `clippy::large_enum_variant`. `Event::Snapshot` now holds a `Box<Snapshot>`; serde encodes it
  unchanged.
- `IpInfo` required a location (`lat`, `lon`, `city`, `country`). The optional IP check only
  learns an address, so `lat`/`lon` became optional and `city`/`country` may be empty, rather than
  inventing a location.
- The spec places observations ("UAPI poll results, network-change observations, child exits")
  on the engine's channel. The engine runs on one thread and *pulls* those observations from the
  platform on each tick, so the single channel carries only commands, ticks, the IP-check result,
  and stop. The ordering guarantee is the same (one owner, sequential execution) and it makes
  every test deterministic: the fake clock and the order of platform calls are the whole input.
- The connect "transaction" is not one blocking call. Steps 0-4 run synchronously within one
  command. The handshake gate is a phase advanced by 250 ms ticks, and steps 6-8 run when the
  handshake appears. The engine therefore keeps serving commands during the 15 s gate, and
  disconnect cancels it, instead of answering `busy` for 15 s.
- `wireguard-tools` is not installed here, so wg-quick's darwin semantics follow the published
  `darwin.bash`, confirmed against the wireguard-go and wireguard-tools sources:
  - v4 addresses use `ifconfig utunN inet A/P A alias`; v6 use `ifconfig utunN inet6 A/P alias`.
  - Then `ifconfig utunN mtu M up`. The MTU is the profile's, else the physical MTU minus 80, else
    1420.
  - Split routes use `route -q -n add -inet 0.0.0.0/1 -interface utunN` (and the other three).
  - The endpoint route uses `route -q -n add -inet <ip> -gateway <gw>`.
  - Teardown removes the UAPI socket, which makes wireguard-go exit.

## Profiles

- Profile identity is the peer public key. A first import assigns
  `slug(name)-<6 hex of sha256(peer key)>`. Re-importing the same peer keeps that id, even if
  `--name` changes the name, so recents and the TUI selection survive. On the rare collision of
  slug and 6 hex digits, 12 hex digits are used.
- A country is derived only from two **upper-case** letters at the start of the name, followed by
  a non-letter (`CO#4`, `US-NY#123`). Lower-case or longer prefixes (`my-vpn`, `CORP-1`) yield
  none, which avoids false matches such as `my` → Malaysia. `UK` and `EL`, ISO's exceptional
  reservations, map to GB and GR because providers use them.
- `--country` accepts any two letters; an unknown code is shown raw. A profile with no country is
  grouped as "No country" with code `--`. City is empty unless `--city` is given; the TUI shows
  an empty city as "—".
- `--name` with more than one file is refused, since every profile would get the same name.
- Endpoints must be IPv4: the endpoint host route is pinned through the physical IPv4 gateway,
  and IPv6 endpoint pinning is not implemented. IPv6 endpoints are rejected with a clear message.
- `DNS =` must be IP addresses; search domains are rejected rather than half-applied.
- MTU must be 1280-9000.
- `PersistentKeepalive` from the config is honored when non-zero; otherwise 25 s.
- `ListenPort` and any other unknown key produce a warning (key name only) and are ignored.
- AllowedIPs without `0.0.0.0/0` imports with a warning; the narrower networks are routed in
  addition to the split defaults. A config without DNS imports with a warning.
- The parser strips a UTF-8 BOM, CRLF, full-line `#`/`;` comments, and trailing `#` comments. The
  first full-line comment inside `[Peer]` is the name candidate. Control characters are removed
  and names are capped at 64 characters.
- Parse errors never echo values, and a file read for import is limited to 64 KiB.
- Stored profiles are versioned JSON (`format: 1`). Keys are kept as base64; the store is the only
  code with a serializer for them.

## Engine

- **Exceptions come from the journal.** An endpoint or tunnel interface is passed by pf exactly
  while its journal entry exists. Undoing an entry means recomputing the policy without it. This
  is why "remove the entry after the undo succeeds" and the policy can never disagree.
- **Teardown stops at the first failed undo** and retries the rest on later ticks, preserving
  reverse order: a tunnel's pass rule is never removed after its wireguard-go is gone. While
  leftovers exist with no session, the tunnel reports `disconnecting`, and `connect` returns
  `busy` (the spec's "no other tunnel active").
- **Switching servers.** The new endpoint exception is added first, then the old session is torn
  down in full, then the new one is brought up. While armed, the policy covers both endpoints only
  during the switch.
- **Connecting to the current server is idempotent.** It applies while connected or during the
  initial handshake. During reconnects, connecting to the same server starts a fresh connect: this
  is "reconnect now".
- **Reconnect attempts.**
  - A soft attempt re-pins the endpoint route, then re-sends the endpoint and toggles
    `persistent_keepalive_interval` from 0 to N. wireguard-go sends an immediate keepalive, and
    therefore a handshake when the session has expired, only on a 0 → N change.
  - A soft attempt succeeds when a handshake newer than the attempt appears within 5 s.
  - A hard attempt tears down everything except the endpoint exception and brings the tunnel up
    again behind its own 15 s gate.
  - A dead wireguard-go or a vanished utun forces hard attempts, and its pass rule is removed
    immediately.
  - Attempts never stop; the backoff caps at 15 s.
- **Offline.** No default route means `reconnecting` with reason "network offline" and no
  attempts. When the route returns, attempt 1 starts immediately.
- **Network change.** A change in gateway, interface, or interface address while connected
  re-pins the endpoint route and refreshes the peer, without changing the reported state. A
  wall-clock gap above 5 s between ticks counts as a wake-up and is handled the same way.
- **`last_error`** is `"<code>: <detail>"`. Precondition failures (`binary_untrusted`,
  `no_network`, `unknown_server`, `no_profiles`, `busy`) are returned to the caller and leave the
  tunnel state as it was.
- **Arming** persists `armed=true` first, then loads the policy and enables pf. The kill switch
  reports `armed` only when both the load and `pfctl -E` succeeded; otherwise `error`, with the
  intent kept so a restart fails closed. A failed persist reverts the in-memory change.
- **Disarming** persists `armed=false` first, then flushes the anchor and releases the token. If
  the flush fails, the intent is restored to armed.
- **Settings.** A tightening change (allow_lan on → off, block_ipv6 off → on) is loaded into pf
  before it is persisted, and is rejected if pf refuses it. A loosening change is persisted first.
  Either way a partial failure leaves the stricter setting in force.
- **States are flushed** (`pfctl -F states`) when arming and on settings-level tightening, not
  when exceptions are swapped.
- **Corrupt or unreadable state** at startup is treated as armed (fail closed).
- **When starting disarmed**, the daemon flushes the anchor anyway and releases any leftover token
  (invariant I3).
- **pf tokens.** At an armed startup a fresh token is taken before the previous one is released,
  so pf never drops to zero references. `pf_enabled_by_us` records whether pf was disabled before
  vpnuid enabled it. Rescue releases the token, or disables pf only when vpnuid enabled it and no
  token is known.
- **Recents and quick connect.** Recents (5, most recent first) update when a session reaches
  Connected. Quick connect uses the first recent that still exists, else the most recently
  imported profile; the TUI mirrors this rule to name the target.

## Kill switch policy

- **Anchor name.** `com.apple/000.vpnui`. The stock `/etc/pf.conf` evaluates
  `anchor "com.apple/*"`, and pf walks that wildcard's children in name order. `000.` sorts before
  Apple's numbered sub-anchors (`200.AirDrop`, `250.ApplicationFirewall`), and every rule is
  `quick`, so our decision is final. `/etc/pf.conf` is never edited. `vpnuid doctor` verifies
  that the anchor is really evaluated.
- **`flags any`.** Running the planned rules through `pfctl -n` showed that a bare
  `pass ... keep state` becomes `flags S/SA keep state`, which creates state only on TCP SYN.
  Because states are flushed when arming, established loopback, tunnel, and LAN connections would
  then be blocked. The loopback, tunnel, and LAN rules therefore use `flags any keep state`.
- **LAN rules carry a direction:** `pass out ... to <lan>` and `pass in ... from <lan>`. A
  `from <lan>` rule without a direction would match every outbound packet, since your own address
  is in the LAN range.
- **`block_ipv6`.** When armed, the final `block drop quick all` already blocks IPv6, so the rule
  is defence in depth and does not change behavior. IPv6 outside the tunnel while disarmed is
  prevented only by routing `::/1` and `8000::/1` into the tunnel while connected; the anchor is
  empty when disarmed (I3).
- The renderer's output is checked by golden tests for all 48 combinations and by the real pf
  parser. `pfctl -n -f` needs no privileges and loads nothing, and the test is skipped where
  pfctl is absent.

## DNS

- **Keys.**
  - Key: `State:/Network/Service/6A1C9E8B-3D4F-4E2A-9B7C-5D8E0F1A2B3C/DNS`.
  - `ServerAddresses` holds the profile's DNS servers.
  - `SupplementalMatchDomains = [""]`: the empty domain matches everything.
  - `SupplementalMatchOrders = [1]`: the lowest order wins among resolvers that match equally.
- **Why these keys.** configd (IPMonitor) honors a State-only service with no Setup entry as long
  as it is supplemental, and strips `SearchDomains`/`SearchOrder` from such services, so they are
  not set.
- **Lifetime.** The key is created with `add <key> temporary` by an `scutil` process that vpnuid
  keeps running with its stdin open. configd removes a session's temporary keys when the session
  ends. If vpnuid dies, the pipe closes, scutil exits, and the override disappears without any
  recovery code running.
- **Teardown.** vpnuid closes the session and also issues `remove <key>` (tolerating "No such
  key"); recovery and rescue issue the same remove.
- **Verification.** After writing, vpnuid confirms the key with `scutil` `show` before reporting
  success.
- Persistent settings (`networksetup -setdnsservers`) are never touched. Tailscale's tailscaled
  uses the same synthetic-service technique; Mullvad instead rewrites every service's DNS and
  restores it.

## Processes and privileges

- **Pinned binaries.** `install` pins both wireguard-go and vpnuid; the LaunchDaemon runs the
  pinned vpnuid. A trusted path must be canonical (no symlink anywhere, which also rules out
  macOS's `/var` → `/private/var`). Every component must be root-owned and not group- or
  world-writable.
- **Orphan check.** An orphaned wireguard-go is killed only if `/var/run/vpnui/wg/wireguard-go.pid`
  names a process whose `ps -o comm=` path equals the pinned path.
- **Child processes.** wireguard-go runs as `-f utun` with only `WG_TUN_NAME_FILE` and
  `LOG_LEVEL=error` in its environment and stdio discarded. vpnuid waits up to 5 s for the name
  file and the UAPI socket. Each UAPI transaction uses a fresh connection, since a connection is
  unusable after a set error. The response `errno` is signed (wireguard-go reports `-22`).
- **System tools.** They run through one helper: absolute path, argument vector, cleared
  environment, 10 s timeout, and kill-on-drop. Long-lived children (wireguard-go, the DNS scutil
  session) are also killed on drop.
- **The socket.**
  - `/var/run/vpnui` is created or forced to 0700 root before binding.
  - The socket is chowned to `root:<gid>`, where the gid comes from the install record or
    `SUDO_GID`, and set to 0660. Only then is the directory opened to 0755.
  - A stale socket is removed only if connecting to it fails; a non-socket file at that path is an
    error.
- **Refusals.** A refused peer receives one line with id 0 (`unauthorized` or `busy`) before the
  connection is closed, so the TUI can say why.
- **Allowed users** are uid 0, the uid recorded by `install --user`, and `SUDO_UID` when `run` is
  started under sudo.
- **The IP check** is one HTTPS request per transition to Connected, run as `curl` with
  `--proto =https` and `--max-time 5`. It runs under uid and gid `nobody`, with the URL passed as
  a single `--url` argument. The URL is restricted to `https://` and printable ASCII. A result is
  applied only if the tunnel is still connected. This uses the system's curl instead of adding a
  TLS stack.
- **Shutdown.** SIGTERM/SIGINT tear the tunnel down and keep an armed policy and its pf token;
  the socket file is removed. `--auto-rescue-after` runs the full rescue, then exits.

## install, uninstall, rescue, doctor

- **Install** refuses (and `--dry-run` warns) when any parent of `/usr/local/libexec/vpnui` is not
  root-owned. That is the Intel Homebrew case, where `/usr/local` subdirectories belong to the
  user. `--yes` is required after reviewing the printed hashes.
- **Uninstall** runs rescue first and removes only what install created. Imported profiles and
  the state file stay; the command prints how to remove them.
- **Rescue** works from the state file's journal and needs neither the daemon nor the network:
  1. `launchctl bootout` if the plist exists.
  2. Stop wireguard-go (pidfile and path check).
  3. Delete journaled routes.
  4. Remove the DNS key.
  5. Flush both anchors.
  6. Release the token, or disable pf only if vpnuid enabled it.
  7. Write a disarmed state with an empty journal, keeping settings and recents.
  8. Remove the socket.

  Run it after stopping a foreground daemon; rescue does not stop a daemon running outside
  launchd.
- **Doctor's self-test** sends its probe with a plain UDP socket and reads the rule's `Packets:`
  counter from `pfctl -a <anchor> -v -s rules`. It enables pf temporarily, with its own token,
  only if pf was disabled.
- **`list`** reads the store as root; without root it asks the running daemon.

## Audit and tests

- **Ground truth for the audit.** The audit reads only the fake's kernel model, the persisted
  state file, and the test's own record of requested endpoints. I1 and I2 are checked after every
  platform call. "Armed implies enforced or an error is reported" and I3 are checked between
  engine steps, because arming and disarming are multi-call sequences.
- **I1 and LAN rules.** I1 checks LAN rules in the safety direction only: LAN passes imply
  `allow_lan`. LAN being allowed but not yet passed is not a leak.
- **I2's route clause during recovery.** The route clause ("no route into a tunnel without a pass
  rule") is suspended while startup recovery runs. I4 requires the baseline block-all to load
  before leftovers are undone, so routes left by a crash are deliberately black-holed for that
  interval.
- **One wireguard-go instance at most.** The audit also checks this.
- **Randomized test.** It runs 2,000 seeded sequences of 40 steps by default, using its own
  SplitMix PRNG rather than proptest. `VPNUID_RANDOM_RUNS` and `VPNUID_RANDOM_SEED` scale or
  replay it. It found four engine bugs during development, all fixed:
  1. Two instances after a failed switch teardown.
  2. "Armed" reported while pf was disabled.
  3. Intent kept in memory after a failed persist.
  4. A tightened setting recorded before it was enforced.
- **Crashes.** The fake simulates a crash by panicking with a sentinel after a chosen call; the
  test catches it and drops the engine without cleanup.

## Dependencies added

- `nix`: uid lookup, signals, and euid, without `unsafe`.
- `zeroize`: wiping key material.
- `sha2`: binary pinning and profile ids.
- `base64`: WireGuard keys.

Hex encoding is a ten-line helper.

## TUI and mock (v2)

- The default socket is `/var/run/vpnui/vpnui.sock`; the mock keeps `$TMPDIR/vpnui.sock`, so the
  mock needs `--socket`.
- **Quick-connect target.** The footer, rail button, and narrow status bar name it only for
  catalogs of imported profiles (`profile_id` present). The mock picks the least busy server
  instead, so the TUI does not guess there.
- **Missing values.** Group average load is computed over known loads only and shows "—" when
  none are known; "Least busy" considers only servers with a known load. Unknown features render
  as "—".
- **Sorting.** Load and latency sorts are offered only when some server has that data. An
  unavailable sort falls back to name; an empty server list (as right after a reconnect) keeps the
  user's choice.
- **Rejections and errors.** Rejection toasts show a sentence and the code. The daemon's message
  goes to the event log. A response with code `unauthorized` or `busy` for an unknown request id
  raises a toast too.
- **No location.** An `IpInfo` without coordinates never becomes the user's location, so no "you"
  marker or route line is drawn from it.
- **Detail pane.** It gains "Entry" and "Imported" lines when those fields exist.
- **Mock.** It speaks v2: `profiles_count` equals its server count, it accepts `reload_profiles`,
  and its servers carry entry IPs and no `profile_id`.
