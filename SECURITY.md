# Security

## What is being protected

1. **Traffic privacy.** While the kill switch is armed, no packet leaves the machine except
   through the tunnel, to the tunnel's endpoint, DHCP, and (if you allow it) the local network.
2. **Key material.** WireGuard private and preshared keys from imported configs.
3. **The system.** vpnuid runs as root; nothing it does may hand root to anyone else.

## Trust boundaries

| Boundary | Direction | Mechanism |
|---|---|---|
| `vpnui` (your user) → `vpnuid` (root) | commands | Unix socket in `/var/run/vpnui`, peer-uid check on every connection |
| `.conf` file → vpnuid | data | strict typed parser; hard rejects; no execution |
| vpnuid → wireguard-go | execution | pinned path, root-owned parents, SHA-256 re-verified before every launch |
| vpnuid → system tools | execution | absolute paths, argument arrays, cleared environment, timeouts |
| vpnuid → pf | policy | rules rendered only from typed values; one anchor; atomic reloads |
| vpnuid → the network | requests | none, except the tunnel and the opt-in IP check |

## Defended

- **Configs cannot run code.** `PreUp`, `PostUp`, `PreDown`, `PostDown`, `SaveConfig`, `Table`, and
  `FwMark` are rejected at import. Nothing from a config is ever passed to a shell or formatted
  into a command line; there is no shell anywhere in vpnuid.
- **No resolution outside the tunnel.** Hostname endpoints are rejected, so connecting never
  needs DNS before the tunnel exists.
- **Keys stay inside the daemon.**
  - Keys have a redacting `Debug`, are zeroized on drop, and have no `Serialize` or `Display`
    implementation; the only serializer is the profile store.
  - Keys reach wireguard-go over its root-only UAPI socket, never through argv or environment
    variables.
  - UAPI responses, which include the private key, are held in zeroizing buffers and parsed
    without keeping that line.
  - Parse errors name keys and line numbers, never values.
  - Tests scan logs, events, the state file, and `Debug` output for every encoding of the test
    keys.
- **Only you can drive the daemon.** The socket is root:your-group 0660 in a directory that is
  0700 until the socket's permissions are set. Every connection's peer uid is checked: root and
  the user recorded at install (or the `sudo` caller for `vpnuid run`) are accepted; anyone else
  receives `unauthorized` and is disconnected before a byte is read. At most 8 clients, 1 MiB per
  line.
- **No user-writable binary runs as root.**
  - `install` copies wireguard-go and vpnuid into `/usr/local/libexec/vpnui/` (root:wheel 0755)
    and records their hashes.
  - Before each wireguard-go launch, vpnuid re-checks the hash, that the path is canonical (no
    symlinks), and that every component is root-owned and not group- or world-writable.
  - The LaunchDaemon runs the pinned copy of vpnuid, never your build directory.
  - This matters on Apple silicon, where the Homebrew prefix belongs to your user.
- **Fail closed.**
  - Arming loads a default-deny policy; afterwards the engine only swaps narrow exceptions.
  - Exceptions are journaled before they are applied, and a pass rule for a tunnel interface
    exists only while that interface's wireguard-go instance does.
  - At startup an armed daemon loads the baseline block-all policy before recovery and before the
    socket exists.
  - A crash or SIGKILL leaves the pf rules in the kernel.
  - A connect that fails while armed leaves block-all, never an open policy.
  - A tighter setting is enforced before it is recorded; a looser one is recorded before it is
    applied.
- **DNS cannot be pinned to a dead tunnel.** The override is a SystemConfiguration key added as
  `temporary` by a `scutil` session that vpnuid holds open; when vpnuid dies, scutil reads EOF
  and exits and configd drops the key. Nothing is written to persistent network settings.
- **Least privilege for the optional IP check.** curl runs as `nobody`, HTTPS only, with a 5 s
  limit, and only while connected.

## Not defended

- **Malware running as your user.** It can open the socket and do anything the TUI can:
  disconnect, disarm the kill switch, allow LAN traffic, or connect elsewhere. vpnuid cannot
  tell your keystrokes from such a process. This design does not defend against malware
  already running as you.
- **Root compromise.** Any root process can flush the anchor, disable pf, read the profile
  store, or replace the pinned binaries (vpnuid would then refuse to launch the changed
  wireguard-go, but the system is already lost).
- **The boot window.** Rules are gone after a reboot until vpnuid starts and reloads them; see
  the README's known limitations.
- **The VPN server and provider.** They see your traffic leaving the tunnel and know your
  account. vpnui does not change that.
- **Other pf users.** Another tool that flushes all anchors, reloads `/etc/pf.conf`, or
  disables pf removes the kill switch. `vpnuid doctor` reports the anchor's state; the daemon
  does not watch for this.
- **Resolver precedence.** Interface-scoped DNS queries and more specific resolver domains
  bypass the override (see README).
- **Traffic analysis and timing.** Packet sizes and timing through the tunnel are visible to an
  observer on the local network.
- **Behavior of macOS internals not verified here.** pf anchor ordering, route semantics, utun,
  and configd DNS precedence are checked only by the manual test (docs/MANUAL_TEST.md). An OS
  update could change any of them; run `vpnuid doctor` after updating macOS.

## Reporting

This is a personal project. If you find a problem, open an issue in the repository you got it
from, describing the class of problem rather than a working exploit.
