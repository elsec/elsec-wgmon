/// Installs an nftables table that drops all traffic except:
///   - loopback
///   - traffic on the active WireGuard interfaces
///   - UDP to/from each peer port (so wg-quick can establish tunnels)
///   - DNS (so hostname-based endpoints can be resolved by wg-quick)
///
/// The table persists across wg-quick down/up cycles, preventing leaks.
/// Call disable() to remove it when all VPNs are intentionally brought down.

/// Parse the peer endpoint port from /etc/wireguard/<profile>.conf.
/// Returns None if no Endpoint line is found.
pub fn peer_port(profile: &str) -> Option<u16> {
    let path = format!("/etc/wireguard/{profile}.conf");
    let contents = std::fs::read_to_string(path).ok()?;
    peer_port_from_str(&contents)
}

fn peer_port_from_str(contents: &str) -> Option<u16> {
    for line in contents.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Endpoint") {
            // Endpoint = host:port  or  [::1]:port
            let rest = rest.trim_start_matches(|c: char| c == ' ' || c == '=').trim();
            let port_str = rest.rsplit(':').next()?;
            return port_str.parse().ok();
        }
    }
    None
}

fn peer_ports(interfaces: &[&str]) -> Vec<u16> {
    let mut ports: Vec<u16> = interfaces
        .iter()
        .filter_map(|iface| peer_port(iface))
        .collect();
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        ports.push(51820);
    }
    ports
}

fn nft_set(items: &[impl std::fmt::Display]) -> String {
    let inner = items
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{ {inner} }}")
}

pub async fn enable(interfaces: &[&str]) -> anyhow::Result<()> {
    if interfaces.is_empty() {
        return disable().await;
    }

    let ports = peer_ports(interfaces);
    let iface_set = nft_set(&interfaces.iter().map(|i| format!("\"{i}\"")).collect::<Vec<_>>());
    let port_set = nft_set(&ports);

    let script = format!(
        r#"
table inet wgmon {{
    chain input {{
        type filter hook input priority -100; policy drop;
        iifname lo accept
        iifname {iface_set} accept
        udp sport {port_set} accept
        ct state established,related accept
    }}
    chain output {{
        type filter hook output priority -100; policy drop;
        oifname lo accept
        oifname {iface_set} accept
        udp dport {port_set} accept
        udp dport 53 accept
        tcp dport 53 accept
        ct state established,related accept
    }}
    chain forward {{
        type filter hook forward priority -100; policy drop;
    }}
}}
"#
    );

    // Delete any existing table first (idempotent).
    let _ = tokio::process::Command::new("nft")
        .args(["delete", "table", "inet", "wgmon"])
        .output()
        .await;

    let output = tokio::process::Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?
        .wait_with_input_and_output(script.as_bytes())
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nft enable killswitch failed: {stderr}");
    }

    tracing::info!(interfaces = ?interfaces, ports = ?ports, "kill switch enabled");
    Ok(())
}

pub async fn disable() -> anyhow::Result<()> {
    let exists = tokio::process::Command::new("nft")
        .args(["list", "table", "inet", "wgmon"])
        .output()
        .await?
        .status
        .success();

    if !exists {
        tracing::info!("kill switch already disabled");
        return Ok(());
    }

    tracing::info!("disabling kill switch");

    let output = tokio::process::Command::new("nft")
        .args(["delete", "table", "inet", "wgmon"])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nft disable killswitch failed: {stderr}");
    }

    tracing::info!("kill switch disabled");
    Ok(())
}

// Convenience extension: write stdin and collect output from a spawned child.
trait SpawnExt {
    async fn wait_with_input_and_output(
        self,
        input: &[u8],
    ) -> std::io::Result<std::process::Output>;
}

impl SpawnExt for tokio::process::Child {
    async fn wait_with_input_and_output(
        mut self,
        input: &[u8],
    ) -> std::io::Result<std::process::Output> {
        use tokio::io::AsyncWriteExt;
        if let Some(mut stdin) = self.stdin.take() {
            stdin.write_all(input).await?;
        }
        self.wait_with_output().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_parsed_from_ipv4_endpoint() {
        assert_eq!(peer_port_from_str("Endpoint = 1.2.3.4:51820"), Some(51820));
    }

    #[test]
    fn port_parsed_from_ipv6_endpoint() {
        assert_eq!(peer_port_from_str("Endpoint = [::1]:51820"), Some(51820));
    }

    #[test]
    fn port_parsed_from_hostname_endpoint() {
        assert_eq!(
            peer_port_from_str("Endpoint = vpn.example.com:51820"),
            Some(51820)
        );
    }

    #[test]
    fn port_parsed_from_full_config() {
        let conf = "[Interface]\nPrivateKey = abc\n\n[Peer]\nPublicKey = xyz\nEndpoint = vpn.example.com:1234\nAllowedIPs = 0.0.0.0/0\n";
        assert_eq!(peer_port_from_str(conf), Some(1234));
    }

    #[test]
    fn no_endpoint_returns_none() {
        assert_eq!(peer_port_from_str("[Interface]\nPrivateKey = abc\n"), None);
    }

    #[test]
    fn peer_ports_deduplicates() {
        // When two interfaces share the same port, only one entry should appear.
        // We can't test peer_port() without real files, so test the dedup logic directly.
        let mut ports = vec![51820u16, 51820];
        ports.sort_unstable();
        ports.dedup();
        assert_eq!(ports, vec![51820]);
    }

    #[test]
    fn nft_set_single_item() {
        assert_eq!(nft_set(&["51820"]), "{ 51820 }");
    }

    #[test]
    fn nft_set_multiple_items() {
        assert_eq!(nft_set(&["51820", "51821"]), "{ 51820, 51821 }");
    }
}
