# wgmon

A daemon that monitors iwd D-Bus events and automatically brings WireGuard up or down based on the connected WiFi SSID.

- **Untrusted network** (or no WiFi) → `wg-quick up <profile>`
- **Allowlisted (trusted) network** → `wg-quick down <profile>`
- **Network switch** → cycles the tunnel so WireGuard re-establishes with the new route

## Requirements

- [iwd](https://iwd.wiki.kernel.org/) as the WiFi manager
- `wg-quick` (from the `wireguard-tools` package)
- A working WireGuard config at `/etc/wireguard/<profile>.conf`

## Installation

```bash
sudo make install
```

This builds the release binary, installs it to `/usr/local/bin/wgmon`, installs the systemd template unit, creates `/etc/wgmon/`, and reloads systemd.

To uninstall:

```bash
sudo make uninstall
```

Config files in `/etc/wgmon/` are left intact on uninstall.

## Configuration

Create `/etc/wgmon/<profile>.toml` — one file per WireGuard profile:

```toml
# SSIDs where WireGuard will NOT connect (trusted networks).
# On all other SSIDs, or when WiFi is disconnected, WireGuard comes up.
allowlist = ["HomeNetwork", "WorkNetwork"]
```

## Enabling the service

```bash
sudo systemctl enable --now wgmon@wg0.service
```

> **Note:** disable `wg-quick@wg0.service` if it's enabled — `wgmon` takes over managing the tunnel and they will conflict.
>
> ```bash
> sudo systemctl disable --now wg-quick@wg0.service
> ```

Multiple profiles are independent:

```bash
sudo systemctl enable --now wgmon@wg0.service
sudo systemctl enable --now wgmon@wg1.service
```

## Logs

```bash
journalctl -u wgmon@wg0 -f
```

## How it works

On startup `wgmon` connects to the system D-Bus and queries iwd's `ObjectManager` to find all connected stations and their SSIDs. It then subscribes to `PropertiesChanged` signals on `net.connman.iwd.Station` and re-evaluates on every `State` or `ConnectedNetwork` change.

**Reconciliation policy**: any connected SSID not in the allowlist → VPN up. If no WiFi at all → VPN up (safe default). All connected SSIDs are trusted → VPN down. On any SSID change while VPN is needed, the tunnel is cycled (`down` then `up`) to force a fresh handshake over the new network.
