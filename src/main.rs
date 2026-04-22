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
const DEBOUNCE_DELAY: Duration = Duration::from_secs(3);
const FAR_FUTURE: Duration = Duration::from_secs(86400 * 365 * 30);

#[derive(serde::Deserialize, Debug)]
struct WlanRule {
    ssid: String,
    #[serde(rename = "wg-quick", default)]
    wg_quick: Vec<String>,
}

#[derive(serde::Deserialize, Debug, Default)]
struct NetworkConfig {
    #[serde(rename = "wg-quick", default)]
    wg_quick: Vec<String>,
}

#[derive(serde::Deserialize, Debug, Default)]
struct Defaults {
    #[serde(default)]
    wlan: NetworkConfig,
    #[serde(default)]
    ether: NetworkConfig,
    #[serde(default)]
    wwan: NetworkConfig,
}

#[derive(serde::Deserialize, Debug)]
struct Config {
    #[serde(default)]
    wlan: Vec<WlanRule>,
    #[serde(default)]
    default: Defaults,
}

struct State {
    prev_ssids: Option<HashSet<String>>,
    active_interfaces: HashSet<String>,
}

impl State {
    fn new() -> Self {
        State {
            prev_ssids: None,
            active_interfaces: HashSet::new(),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();

    let config: Config = toml::from_str(&std::fs::read_to_string("/etc/wgmon/wgmon.toml")?)?;

    let all_ifaces = all_configured_interfaces(&config);
    tracing::info!(interfaces = ?all_ifaces, "config loaded");

    for iface in &all_ifaces {
        let conf = format!("/etc/wireguard/{iface}.conf");
        if !std::path::Path::new(&conf).exists() {
            anyhow::bail!("{iface} listed in config but {conf} not found");
        }
    }
    tracing::info!("all interface configs validated");

    let conn = Connection::system().await?;

    let startup_ssids: HashSet<String> = get_connected_ssids(&conn)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();
    tracing::info!(ssids = ?startup_ssids, "startup network state");

    let startup_desired = resolve_interfaces(&startup_ssids, &config);
    if !startup_desired.is_empty() {
        tracing::info!(interfaces = ?startup_desired, "untrusted network at startup, enabling kill switch");
        let ifaces: Vec<&str> = startup_desired.iter().map(|s| s.as_str()).collect();
        killswitch::enable(&ifaces).await?;
    } else {
        tracing::info!("trusted network at startup, skipping kill switch");
    }

    let mut state = State::new();
    let result = run(&conn, &config, &mut state).await;

    tracing::info!(interfaces = ?state.active_interfaces, "shutting down — bringing down active interfaces");
    for iface in &state.active_interfaces {
        let _ = wgquick::wg_quick("down", iface).await;
    }
    killswitch::disable().await?;

    result
}

async fn run(
    conn: &Connection,
    config: &Config,
    state: &mut State,
) -> anyhow::Result<()> {
    reconcile(conn, config, state).await?;

    let mut iwd_stream = watch_station_changes(conn).await?;
    let mut wake_stream = watch_wake(conn).await?;
    let mut watchdog = time::interval(WATCHDOG_INTERVAL);
    watchdog.tick().await; // discard the immediate first tick
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let debounce = time::sleep(FAR_FUTURE);
    tokio::pin!(debounce);

    loop {
        tokio::select! {
            item = iwd_stream.next() => {
                if item.is_none() { break; }
                tracing::debug!("network change detected, debouncing for {}s", DEBOUNCE_DELAY.as_secs());
                debounce.as_mut().reset(tokio::time::Instant::now() + DEBOUNCE_DELAY);
            }
            _ = &mut debounce => {
                debounce.as_mut().reset(tokio::time::Instant::now() + FAR_FUTURE);
                tracing::debug!("debounce elapsed, reconciling");
                reconcile(conn, config, state).await?;
            }
            item = wake_stream.next() => {
                if item.is_none() { break; }
                tracing::info!("system wake detected, forcing reconcile");
                debounce.as_mut().reset(tokio::time::Instant::now() + FAR_FUTURE);
                state.prev_ssids = None;
                reconcile(conn, config, state).await?;
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
                if state.active_interfaces.is_empty() {
                    tracing::debug!("watchdog: no active interfaces, skipping");
                } else {
                    tracing::debug!(interfaces = ?state.active_interfaces, "watchdog: checking handshakes");
                    let stale = wgquick::stale_interfaces(&state.active_interfaces).await;
                    if stale.is_empty() {
                        tracing::debug!("watchdog: all interfaces healthy");
                    } else {
                        tracing::warn!(stale = ?stale, "watchdog: stale interfaces detected, forcing reconcile");
                        state.prev_ssids = None;
                        reconcile(conn, config, state).await?;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn reconcile(
    conn: &Connection,
    config: &Config,
    state: &mut State,
) -> anyhow::Result<()> {
    let ssids: HashSet<String> = get_connected_ssids(conn).await?.into_iter().collect();

    if state.prev_ssids.as_ref() == Some(&ssids) {
        tracing::debug!(ssids = ?ssids, "SSIDs unchanged, skipping");
        return Ok(());
    }

    tracing::info!(ssids = ?ssids, active = ?state.active_interfaces, "network state changed");

    let desired = resolve_interfaces(&ssids, config);
    tracing::info!(desired = ?desired, "resolved desired interfaces");

    let desired_set: HashSet<String> = desired.iter().cloned().collect();

    // Interfaces no longer wanted — bring down only, don't cycle.
    let to_bring_down: Vec<String> = state
        .active_interfaces
        .difference(&desired_set)
        .cloned()
        .collect();

    tracing::info!(cycle = ?desired, bring_down = ?to_bring_down, "reconciling interfaces");

    if !desired.is_empty() {
        let ifaces: Vec<&str> = desired.iter().map(|s| s.as_str()).collect();
        killswitch::enable(&ifaces).await?;
    }

    for iface in &to_bring_down {
        tracing::info!(iface, "bringing down interface");
        wgquick::wg_quick("down", iface).await?;
        state.active_interfaces.remove(iface);
    }

    // Always cycle desired interfaces so the tunnel re-establishes on the new network.
    for iface in &desired {
        tracing::info!(iface, "cycling interface");
        wgquick::wg_quick("down", iface).await?;
        wgquick::wg_quick("up", iface).await?;
        state.active_interfaces.insert(iface.clone());
    }

    if desired.is_empty() {
        tracing::info!("all networks trusted, kill switch disabled");
        killswitch::disable().await?;
    }

    state.prev_ssids = Some(ssids);
    Ok(())
}

/// Returns all unique interface names across all config rules, in first-seen order.
fn all_configured_interfaces(config: &Config) -> Vec<String> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut result = Vec::new();
    for iface in config
        .wlan
        .iter()
        .flat_map(|r| r.wg_quick.iter())
        .chain(config.default.wlan.wg_quick.iter())
        .chain(config.default.ether.wg_quick.iter())
        .chain(config.default.wwan.wg_quick.iter())
    {
        if seen.insert(iface.as_str()) {
            result.push(iface.clone());
        }
    }
    result
}

/// Returns the ordered, deduped list of interfaces to bring up for the given SSIDs.
fn resolve_interfaces(ssids: &HashSet<String>, config: &Config) -> Vec<String> {
    let mut desired: Vec<String> = Vec::new();

    if ssids.is_empty() {
        apply_wlan_default(&mut desired, config);
        return desired;
    }

    for ssid in ssids {
        if let Some(rule) = config.wlan.iter().find(|r| r.ssid == *ssid) {
            add_interfaces(&mut desired, &rule.wg_quick);
        } else {
            apply_wlan_default(&mut desired, config);
        }
    }

    desired
}

fn apply_wlan_default(desired: &mut Vec<String>, config: &Config) {
    if !config.default.wlan.wg_quick.is_empty() {
        add_interfaces(desired, &config.default.wlan.wg_quick);
    } else {
        add_interfaces(desired, &all_configured_interfaces(config));
    }
}

fn add_interfaces(desired: &mut Vec<String>, ifaces: &[String]) {
    for iface in ifaces {
        if !desired.contains(iface) {
            desired.push(iface.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(toml: &str) -> Config {
        toml::from_str(toml).unwrap()
    }

    fn ssids(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_wifi_with_default_uses_default() {
        let c = config(r#"
            [[wlan]]
            ssid = "Home"
            "wg-quick" = []

            [default.wlan]
            "wg-quick" = ["wg0"]
        "#);
        assert_eq!(resolve_interfaces(&ssids(&[]), &c), vec!["wg0"]);
    }

    #[test]
    fn no_wifi_no_default_brings_up_all_configured() {
        let c = config(r#"
            [[wlan]]
            ssid = "Home"
            "wg-quick" = ["wg0"]
        "#);
        assert_eq!(resolve_interfaces(&ssids(&[]), &c), vec!["wg0"]);
    }

    #[test]
    fn trusted_ssid_returns_empty() {
        let c = config(r#"
            [[wlan]]
            ssid = "Home"
            "wg-quick" = []
        "#);
        assert!(resolve_interfaces(&ssids(&["Home"]), &c).is_empty());
    }

    #[test]
    fn untrusted_ssid_uses_default() {
        let c = config(r#"
            [[wlan]]
            ssid = "Home"
            "wg-quick" = []

            [default.wlan]
            "wg-quick" = ["wg0"]
        "#);
        assert_eq!(resolve_interfaces(&ssids(&["CoffeeShop"]), &c), vec!["wg0"]);
    }

    #[test]
    fn unmatched_ssid_no_default_brings_up_all() {
        let c = config(r#"
            [[wlan]]
            ssid = "Home"
            "wg-quick" = ["wg0"]
        "#);
        assert_eq!(resolve_interfaces(&ssids(&["CoffeeShop"]), &c), vec!["wg0"]);
    }

    #[test]
    fn multiple_ssids_union_in_config_order() {
        let c = config(r#"
            [[wlan]]
            ssid = "Home"
            "wg-quick" = ["wg0", "wg1"]

            [[wlan]]
            ssid = "Work"
            "wg-quick" = ["wg2"]
        "#);
        let result = resolve_interfaces(&ssids(&["Home", "Work"]), &c);
        // wg0, wg1 from Home; wg2 from Work — order depends on HashSet iteration
        // but all three must be present
        let result_set: HashSet<_> = result.iter().cloned().collect();
        assert_eq!(result_set, HashSet::from(["wg0".into(), "wg1".into(), "wg2".into()]));
    }

    #[test]
    fn first_match_wins_per_ssid() {
        let c = config(r#"
            [[wlan]]
            ssid = "Home"
            "wg-quick" = ["wg0"]

            [[wlan]]
            ssid = "Home"
            "wg-quick" = ["wg1"]
        "#);
        assert_eq!(resolve_interfaces(&ssids(&["Home"]), &c), vec!["wg0"]);
    }

    #[test]
    fn deduplication_across_ssids() {
        let c = config(r#"
            [[wlan]]
            ssid = "Home"
            "wg-quick" = ["wg0"]

            [[wlan]]
            ssid = "Work"
            "wg-quick" = ["wg0", "wg1"]
        "#);
        let result = resolve_interfaces(&ssids(&["Home", "Work"]), &c);
        let result_set: HashSet<_> = result.iter().cloned().collect();
        assert_eq!(result_set, HashSet::from(["wg0".into(), "wg1".into()]));
        assert_eq!(result.iter().filter(|i| i.as_str() == "wg0").count(), 1);
    }

    #[test]
    fn config_parses_all_sections() {
        let c = config(r#"
            [[wlan]]
            ssid = "HomeNetwork"
            "wg-quick" = ["wg0", "wg1"]

            [[wlan]]
            ssid = "WorkNetwork"
            "wg-quick" = ["wg2"]

            [default.wlan]
            "wg-quick" = ["wg0"]

            [default.ether]
            "wg-quick" = []

            [default.wwan]
            "wg-quick" = ["wg0"]
        "#);
        assert_eq!(c.wlan.len(), 2);
        assert_eq!(c.wlan[0].ssid, "HomeNetwork");
        assert_eq!(c.wlan[0].wg_quick, vec!["wg0", "wg1"]);
        assert_eq!(c.default.wlan.wg_quick, vec!["wg0"]);
        assert!(c.default.ether.wg_quick.is_empty());
        assert_eq!(c.default.wwan.wg_quick, vec!["wg0"]);
    }

    #[test]
    fn all_configured_interfaces_deduped() {
        let c = config(r#"
            [[wlan]]
            ssid = "Home"
            "wg-quick" = ["wg0", "wg1"]

            [[wlan]]
            ssid = "Work"
            "wg-quick" = ["wg1", "wg2"]

            [default.wlan]
            "wg-quick" = ["wg0"]
        "#);
        let ifaces = all_configured_interfaces(&c);
        assert_eq!(ifaces, vec!["wg0", "wg1", "wg2"]);
    }
}
