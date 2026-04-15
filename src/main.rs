mod dbus;
mod killswitch;
mod wgquick;

use dbus::{get_connected_ssids, watch_station_changes, watch_wake};
use futures_util::StreamExt;
use std::collections::HashSet;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tokio::time;
use zbus::Connection;

const WATCHDOG_INTERVAL: Duration = Duration::from_secs(60);

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

    // Check current SSIDs before installing the kill switch — no point
    // blocking traffic on a trusted network just because the daemon restarted.
    // On an untrusted network we still install it immediately to close the
    // restart leak window.
    let startup_ssids: HashSet<String> = get_connected_ssids(&conn)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();
    if needs_vpn(&startup_ssids, &allowlist) {
        killswitch::enable(&profile).await?;
    }

    let result = run(&conn, &profile, &allowlist).await;

    // Always remove the kill switch on exit, whether clean or error.
    tracing::info!("removing kill switch on exit");
    killswitch::disable().await?;

    result
}

async fn run(
    conn: &Connection,
    profile: &str,
    allowlist: &HashSet<String>,
) -> anyhow::Result<()> {
    let mut prev_ssids: HashSet<String> = HashSet::new();

    // Initial reconciliation
    reconcile(conn, profile, allowlist, &mut prev_ssids).await?;

    let mut iwd_stream = watch_station_changes(conn).await?;
    let mut wake_stream = watch_wake(conn).await?;
    let mut watchdog = time::interval(WATCHDOG_INTERVAL);
    watchdog.tick().await; // discard the immediate first tick
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            item = iwd_stream.next() => {
                if item.is_none() { break; }
                reconcile(conn, profile, allowlist, &mut prev_ssids).await?;
            }
            item = wake_stream.next() => {
                if item.is_none() { break; }
                tracing::info!("system wake detected, forcing reconcile");
                prev_ssids.clear();
                reconcile(conn, profile, allowlist, &mut prev_ssids).await?;
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received, shutting down");
                break;
            }
            _ = sigint.recv() => {
                tracing::info!("SIGINT received, shutting down");
                break;
            }
            _ = watchdog.tick() => {
                let vpn_should_be_up = needs_vpn(&prev_ssids, allowlist);
                match wgquick::latest_handshake_age(profile).await {
                    Some(age) => {
                        tracing::debug!(age_secs = age.as_secs(), "watchdog: handshake age");
                        if age > wgquick::HANDSHAKE_TIMEOUT {
                            tracing::warn!(age_secs = age.as_secs(), "peer silent, cycling tunnel");
                            prev_ssids.clear();
                            reconcile(conn, profile, allowlist, &mut prev_ssids).await?;
                        }
                    }
                    None if vpn_should_be_up => {
                        tracing::warn!("tunnel unexpectedly down, reconciling");
                        prev_ssids.clear();
                        reconcile(conn, profile, allowlist, &mut prev_ssids).await?;
                    }
                    None => {}
                }
            }
        }
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

    if ssids == *prev_ssids {
        tracing::debug!(ssids = ?ssids, "SSIDs unchanged, skipping");
        return Ok(());
    }

    // No WiFi → safe default: VPN up.
    // Any untrusted SSID → VPN up.
    // All trusted → VPN down.
    let needs_vpn = needs_vpn(&ssids, allowlist);

    if needs_vpn {
        let untrusted: Vec<&String> = ssids.iter().filter(|s| !allowlist.contains(*s)).collect();
        if ssids.is_empty() {
            tracing::info!("no WiFi — bringing VPN up");
        } else {
            tracing::info!(untrusted = ?untrusted, "untrusted network — bringing VPN up");
        }
    } else {
        tracing::info!(ssids = ?ssids, "trusted network — bringing VPN down");
    }

    *prev_ssids = ssids;

    if needs_vpn {
        // Enable kill switch before cycling so there's no leak window.
        killswitch::enable(profile).await?;
        wgquick::wg_quick("down", profile).await?;
        wgquick::wg_quick("up", profile).await
    } else {
        wgquick::wg_quick("down", profile).await?;
        killswitch::disable().await
    }
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
