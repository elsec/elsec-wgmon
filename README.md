# wgmon

A daemon that monitors iwd D-Bus events and automatically brings WireGuard interfaces up or down based on the connected WiFi SSID.

- **Untrusted network** (or no WiFi) → brings up the configured `wg-quick` interfaces
- **Trusted network** → brings them down
- **Network switch** → cycles the tunnel so WireGuard re-establishes over the new route
- **Kill switch** → nftables rules block all non-VPN traffic while any tunnel is active, preventing leaks during cycling

## Requirements

- [iwd](https://iwd.wiki.kernel.org/) as the WiFi manager
- `wg-quick` (from the `wireguard-tools` package)
- WireGuard configs at `/etc/wireguard/<interface>.conf`

## Installation

```bash
sudo make install
```

This builds the release binary, installs it to `/usr/local/bin/wgmon`, installs the systemd unit, creates `/etc/wgmon/`, and reloads systemd.

To uninstall:

```bash
sudo make uninstall
```

Config files in `/etc/wgmon/` are left intact on uninstall.

## Configuration

Create `/etc/wgmon/wgmon.toml`:

```toml
[[wlan]]
ssid = "HomeNetwork"
wg-quick = []              # trusted — no VPN

[[wlan]]
ssid = "WorkNetwork"
wg-quick = ["wg1"]         # split-tunnel: only work VPN

[default.wlan]
wg-quick = ["wg0"]         # any other WiFi or no WiFi → home VPN

[default.ether]
wg-quick = []              # ethernet is trusted (not yet monitored)

[default.wwan]
wg-quick = ["wg0"]         # mobile connection → home VPN (not yet monitored)
```

**Matching rules:**
- Each connected SSID is matched against `[[wlan]]` rules in order — first match wins
- `wg-quick = []` means trusted (no VPN for that network)
- Unmatched SSIDs use the `[default.wlan]` rule; if absent, all configured interfaces come up (fail-secure)
- When connected to multiple SSIDs simultaneously, the union of matched interfaces is used
- All interfaces listed in the config must have a corresponding `/etc/wireguard/<name>.conf` — wgmon errors at startup if any are missing

## Enabling the service

```bash
sudo systemctl enable --now wgmon.service
```

> **Note:** disable `wg-quick@<interface>.service` for any interface wgmon manages — they will conflict:
> ```bash
> sudo systemctl disable --now wg-quick@wg0.service
> ```

## Logs

```bash
journalctl -u wgmon -f
```

## How it works

On startup wgmon reads `/etc/wgmon/wgmon.toml`, validates that all configured interfaces have WireGuard configs, then connects to the system D-Bus and queries iwd's `ObjectManager` for currently connected SSIDs. It subscribes to `PropertiesChanged` signals on `net.connman.iwd.Station` and reconciles on every network state change.

Changes are debounced by 3 seconds to avoid spurious cycling on momentary drops. System wake events (via `org.freedesktop.login1`) bypass the debounce and trigger an immediate reconcile. A watchdog runs every 60 seconds and cycles any interface whose WireGuard handshake has gone silent.

The nftables kill switch is installed before any tunnel is brought up and removed only after all tunnels are down, ensuring there is no window where traffic can leak unprotected.
