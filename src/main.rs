mod dbus;
mod wgquick;

use dbus::{get_connected_ssids, watch_station_changes};
use futures_util::StreamExt;
use std::collections::HashSet;
use zbus::Connection;

#[derive(serde::Deserialize)]
struct Config {
    allowlist: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();

    let profile = std::env::args()
        .nth(1)
        .expect("Usage: wgmon <profile>");

    let config_path = format!("/etc/wgmon/{profile}.toml");
    let config: Config = toml::from_str(&std::fs::read_to_string(&config_path)?)?;
    let allowlist: HashSet<String> = config.allowlist.into_iter().collect();

    let conn = Connection::system().await?;

    let mut prev_ssids: HashSet<String> = HashSet::new();

    // Initial reconciliation
    reconcile(&conn, &profile, &allowlist, &mut prev_ssids).await?;

    // Watch for changes
    let mut stream = watch_station_changes(&conn).await?;
    while stream.next().await.is_some() {
        reconcile(&conn, &profile, &allowlist, &mut prev_ssids).await?;
    }

    Ok(())
}

async fn reconcile(
    conn: &Connection,
    profile: &str,
    allowlist: &HashSet<String>,
    prev_ssids: &mut HashSet<String>,
) -> anyhow::Result<()> {
    let ssids: HashSet<String> = get_connected_ssids(conn).await?.into_iter().collect();

    // No WiFi → safe default: VPN up.
    // Any untrusted SSID → VPN up.
    // All trusted → VPN down.
    let needs_vpn = needs_vpn(&ssids, allowlist);
    let ssids_changed = ssids != *prev_ssids;

    tracing::info!(
        ssids = ?ssids,
        needs_vpn,
        ssids_changed,
        "reconciling"
    );

    if needs_vpn && ssids_changed {
        // SSIDs changed while VPN is needed — cycle the tunnel so WireGuard
        // picks up the new underlying route/handshake.
        tracing::info!("network change detected, cycling tunnel");
        wgquick::wg_quick("down", profile).await?;
    }

    *prev_ssids = ssids;

    wgquick::wg_quick(if needs_vpn { "up" } else { "down" }, profile).await
}

fn needs_vpn(ssids: &HashSet<String>, allowlist: &HashSet<String>) -> bool {
    ssids.is_empty() || ssids.iter().any(|s| !allowlist.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowlist(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn ssids(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_wifi_needs_vpn() {
        assert!(needs_vpn(&ssids(&[]), &allowlist(&["Home"])));
    }

    #[test]
    fn trusted_ssid_no_vpn() {
        assert!(!needs_vpn(&ssids(&["Home"]), &allowlist(&["Home"])));
    }

    #[test]
    fn untrusted_ssid_needs_vpn() {
        assert!(needs_vpn(&ssids(&["CoffeeShop"]), &allowlist(&["Home"])));
    }

    #[test]
    fn any_untrusted_wins() {
        // Connected to both a trusted and untrusted SSID — VPN should come up.
        assert!(needs_vpn(
            &ssids(&["Home", "CoffeeShop"]),
            &allowlist(&["Home"])
        ));
    }

    #[test]
    fn multiple_trusted_no_vpn() {
        assert!(!needs_vpn(
            &ssids(&["Home", "Work"]),
            &allowlist(&["Home", "Work"])
        ));
    }

    #[test]
    fn config_parses() {
        let raw = r#"allowlist = ["HomeNetwork", "WorkNetwork"]"#;
        let config: Config = toml::from_str(raw).unwrap();
        assert_eq!(config.allowlist, vec!["HomeNetwork", "WorkNetwork"]);
    }

    #[test]
    fn empty_allowlist_always_needs_vpn() {
        assert!(needs_vpn(&ssids(&["AnyNetwork"]), &allowlist(&[])));
    }
}
