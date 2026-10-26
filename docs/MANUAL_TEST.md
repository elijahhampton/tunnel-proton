# Manual test (Tier B)

The automated tests prove the engine's logic against a fake platform. This checklist proves it
against real macOS: pf, routes, utun, scutil, and wireguard-go. Run it in order; each step
assumes the previous one passed. Every step lists the command, what you should see, and how to
undo it.

Build first, from the repository root:

```sh
cargo build --release
export VPNUID="$PWD/target/release/vpnuid" VPNUI="$PWD/target/release/vpnui"
```

Note: until step 8, these steps run your build directory's binary with `sudo`. That is your
explicit choice for testing; the installed service runs only the pinned copy.

## Emergency: restoring the network by hand

If something breaks connectivity, run `sudo "$VPNUID" rescue`. If that is unavailable:

```sh
sudo launchctl bootout system/dev.vpnui.daemon 2>/dev/null
sudo pkill -f /usr/local/libexec/vpnui/wireguard-go
sudo pfctl -a com.apple/000.vpnui -F all
sudo route -n delete -inet 0.0.0.0/1;  sudo route -n delete -inet 128.0.0.0/1
sudo route -n delete -inet6 ::/1;      sudo route -n delete -inet6 8000::/1
printf 'remove State:/Network/Service/6A1C9E8B-3D4F-4E2A-9B7C-5D8E0F1A2B3C/DNS\nquit\n' | sudo scutil
```

Then disable pf only if it was off before you started (`sudo pfctl -d`), or reboot: none of
vpnui's network changes survive a reboot.

---

## 0. Harmless checks

### 0a. Rescue on a clean machine

```sh
sudo "$VPNUID" rescue
```

Expected: about a dozen `rescue:` lines such as `launchd service not running`,
`removed the DNS override`, `flushed pf anchor com.apple/000.vpnui`, `no pf token held`. No
errors. Running it twice gives the same output.

Check nothing changed:

```sh
netstat -rn -f inet | head -5          # your normal default route
scutil --dns | head -20                # your normal resolvers
sudo pfctl -s info | head -1           # pf state as before (usually "Status: Disabled")
```

Undo: nothing to undo. The command creates `/var/db/vpnui/state.json` (disarmed); remove it with
`sudo rm -r /var/db/vpnui` if you are not continuing.

### 0b. Doctor

```sh
sudo "$VPNUID" doctor
```

Expected:

- `pf is disabled` (or enabled, matching what you had)
- `kill switch is disarmed`
- `not installed (no install record)` as a warning
- `/var/db/vpnui/profiles is private` (or a warning if it does not exist yet)
- **`pf self-test passed: probe counted (0 -> 1)`**. This is the key result: it proves pf
  evaluates an anchor under `com.apple/` on this macOS version.

If the self-test fails, stop: the kill switch cannot work on this system.

Undo: none. The self-test removes its temporary anchor and restores pf's previous state. Check
with `sudo pfctl -a com.apple/000.vpnui-selftest -s rules` (empty) and `sudo pfctl -s info`.

### 0c. Install dry run

```sh
brew install wireguard-go     # if needed
sudo "$VPNUID" install --dry-run
```

Expected: SHA-256 hashes for wireguard-go and vpnuid, `allowed user <you> (uid 501)`, and the
list of steps (mkdir `/usr/local/libexec/vpnui`, two copies, `install.json`, the plist,
`launchctl bootstrap`). If it prints `warning: install would refuse`, fix the named directory's
ownership before step 8.

Undo: nothing; dry run changes nothing.

## 1. Import configs

Download two or three configs from your account's WireGuard configuration page, at least one
for Colombia.

```sh
sudo "$VPNUID" import ~/Downloads/<colombia>.conf ~/Downloads/<other>.conf
sudo "$VPNUID" list
```

Expected:

- Import prints, for each file, a line like
  `imported .../CO-4.conf as co-4-1a2b3c: Colombia (CO), entry 203.0.113.40:51820`.
- After each file it prints a note that the file still contains a private key and should be
  removed.
- `list` shows a `Colombia (CO)` group. If a name was not recognized, re-run with
  `--country CO`.

Also check:

```sh
sudo ls -la /var/db/vpnui/profiles      # drwx------ root; files -rw------- root
"$VPNUID" list                           # without sudo and without a daemon: explains it needs root or a daemon
```

Undo: `sudo "$VPNUID" remove <id>`. Delete the downloaded files when you are done with them.

## 2. First run

Run the daemon with a five-minute safety net. It needs a root-owned copy of wireguard-go:

```sh
sudo mkdir -p /usr/local/libexec/vpnui
sudo install -o root -g wheel -m 0755 "$(readlink -f "$(brew --prefix)/bin/wireguard-go")" /usr/local/libexec/vpnui/wireguard-go
sudo "$VPNUID" run --auto-rescue-after 300 --wireguard-go /usr/local/libexec/vpnui/wireguard-go
```

In a second terminal:

```sh
"$VPNUI"
"$VPNUID" status
ls -la /var/run/vpnui/                  # drwxr-xr-x root; vpnui.sock srw-rw---- root:staff
```

Expected: the TUI shows EXPOSED (disconnected, kill switch off), your profiles under
Servers, and "IP: not checked" on the posture card. `status` prints `protocol v2`. After 300 s
the daemon logs `auto-rescue timer expired`, runs a rescue, and exits; the TUI then shows
UNKNOWN.

Undo: Ctrl-C in the daemon terminal (a graceful stop), or wait for the auto-rescue.

Restart the daemon the same way for each following step.

## 3. Connect with the kill switch off

In the TUI, open Servers (`2`), select the Colombia profile, and press Enter.

Expected: CONNECTING with phases, then PROTECTED within a few seconds.

```sh
curl -s https://<an IP-lookup service you trust>     # shows a Colombian exit IP
netstat -rn -f inet | grep -E '^(0/1|128.0/1|default)'
route -n get <the endpoint IP>                        # gateway: your router, not utunN
scutil --dns | head -30                               # resolver #1: the profile's DNS server, flags "Supplemental"
sudo scutil -d --dns | grep -i "config id" | head      # Supplemental: 6A1C9E8B-...
ifconfig | grep -A3 '^utun' | head -20                # the tunnel's address and mtu (1420 for a 1500 MTU link)
```

Expected: `0/1` and `128.0/1` point at `utunN`, `default` is unchanged, and the endpoint route
goes through your physical gateway.

Undo: `d` in the TUI. Then check that `netstat -rn` and `scutil --dns` are back to normal.

## 4. Kill switch holds when the tunnel dies

Connect again, then arm the kill switch with `s`. The posture stays PROTECTED.

```sh
sudo pfctl -a com.apple/000.vpnui -s rules      # pass rules for lo0, DHCP, the endpoint, utunN; ends with block drop quick all
sudo pfctl -s info | head -1                    # Status: Enabled
```

Find your physical interface (`route -n get default | grep interface`) and, in a third terminal:

```sh
sudo tcpdump -ni <phys-if> 'not udp port 51820 and not port 67 and not port 68'
```

Adjust 51820 if your endpoint uses another port. Now kill wireguard-go:

```sh
sudo pkill -f /usr/local/libexec/vpnui/wireguard-go
curl --max-time 5 -sS https://example.com; echo "exit=$?"
```

Expected:

- The TUI shows BLOCKED and "Tunnel dropped (wireguard-go exited); reconnecting".
- `curl` fails (exit 7 or 28) and does not print a page.
- **tcpdump shows nothing** while the tunnel is down.

Undo: let step 5 reconnect, or `sudo "$VPNUID" rescue`.

## 5. Recovery: reconnect, network changes, sleep

Wait without touching anything. Expected: after about a second, the TUI goes from Reconnecting
to PROTECTED with a new `utunN`.

Then try each of these, watching the TUI and `route -n get <endpoint>`:

1. Turn Wi-Fi off. Expected: Reconnecting with the reason "network offline", no churn, and
   tcpdump stays quiet. Turn it back on. Expected: PROTECTED again within a few seconds.
2. Switch to another network, such as a phone hotspot. Expected: the endpoint route follows the
   new gateway (`route -n get <endpoint>`) and the tunnel reconnects.
3. Sleep the laptop for a minute and wake it. Expected: the daemon logs "wall clock jumped" and
   the tunnel is PROTECTED again shortly after.

Undo: none needed.

## 6. IPv6

```sh
curl -6 --max-time 5 -sS https://<an IPv6 IP-lookup service you trust>; echo "exit=$?"
netstat -rn -f inet6 | grep -E '^(::/1|8000::/1)'
```

Expected:

- With the kill switch armed: the request fails.
- Disarmed but connected: it fails, or shows the tunnel's IPv6 address if the profile has one.
- **It must never show your ISP's IPv6 address.**
- Both `::/1` and `8000::/1` point at `utunN`.

Undo: none.

## 7. Disconnect while armed, then rescue

With the kill switch armed and connected, press `d`. The confirm dialog reads "Kill switch is
armed. Disconnecting will block all traffic." Choose **Disconnect, stay blocked**.

Expected: the posture is BLOCKED and `curl --max-time 5 https://example.com` fails.

Stop the daemon with Ctrl-C in its terminal. A graceful stop leaves the armed policy in place,
so `curl` still fails. Then:

```sh
sudo "$VPNUID" rescue
netstat -rn -f inet | grep -E '^(0/1|128.0/1)'      # nothing
scutil --dns | grep -c 10.                          # the profile's DNS server is gone
sudo pfctl -sA                                      # anchors listed; ours, if present, is empty:
sudo pfctl -a com.apple/000.vpnui -s rules          # (empty)
sudo pfctl -s info | head -1                        # back to what you had before step 4
```

Expected: normal connectivity returns. The TUI shows UNKNOWN, because the daemon is stopped.

Undo: rescue is the undo.

## 8. Install the service and reboot

Only after steps 0-7 passed:

```sh
sudo "$VPNUID" install --yes
sudo launchctl print system/dev.vpnui.daemon | head -20      # state = running
"$VPNUI"
```

Arm the kill switch in the TUI, then reboot. After logging in:

```sh
"$VPNUID" status          # kill switch Armed, tunnel Disconnected
sudo "$VPNUID" doctor     # anchor has rules: true; pinned binaries match
```

Expected: BLOCKED right after login, with no traffic until you connect.

The interval between the network coming up and launchd starting vpnuid is the known boot
window (see the README). To observe it, run `sudo tcpdump -ni <phys-if>` from a second account
as early as possible after boot, and compare its timestamps with the first line of
`/var/log/vpnui/vpnuid.log`.

Undo: `sudo "$VPNUID" uninstall`. It runs a rescue and removes the plist, the pinned binaries,
and `install.json`; imported profiles stay in `/var/db/vpnui/profiles`.
