/// Installs an nftables table that drops all traffic except:
///   - loopback
///   - traffic on the WireGuard interface
///   - UDP to/from the peer port (so wg-quick can establish the tunnel)
///   - DNS (so hostname-based endpoints can be resolved by wg-quick)
///
/// The table persists across wg-quick down/up cycles, preventing leaks.
/// Call disable() to remove it when the VPN is intentionally brought down.

/// Parse the peer endpoint port from /etc/wireguard/<profile>.conf.
/// Returns None if no Endpoint line is found.
pub fn peer_port(profile: &str) -> Option<u16> {
    let path = format!("/etc/wireguard/{profile}.conf");
    let contents = std::fs::read_to_string(path).ok()?;
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

pub async fn enable(profile: &str) -> anyhow::Result<()> {
    let port = peer_port(profile).unwrap_or(51820);

    // Build the full ruleset as a single atomic nft script.
    let script = format!(
        r#"
table inet wgmon {{
    chain input {{
        type filter hook input priority -100; policy drop;
        iifname lo accept
        iifname "{profile}" accept
        udp sport {port} accept
        ct state established,related accept
    }}
    chain output {{
        type filter hook output priority -100; policy drop;
        oifname lo accept
        oifname "{profile}" accept
        udp dport {port} accept
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

    // Delete any existing wgmon table first (idempotent).
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

    tracing::info!(profile, port, "kill switch enabled");
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
        tracing::debug!("kill switch already disabled");
        return Ok(());
    }

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
    #[test]
    fn port_parsed_from_ipv4_endpoint() {
        assert_eq!(parse_port("1.2.3.4:51820"), Some(51820));
    }

    #[test]
    fn port_parsed_from_ipv6_endpoint() {
        assert_eq!(parse_port("[::1]:51820"), Some(51820));
    }

    #[test]
    fn port_parsed_from_hostname_endpoint() {
        assert_eq!(parse_port("vpn.example.com:51820"), Some(51820));
    }

    // Helper that mirrors the parsing logic in peer_port().
    fn parse_port(endpoint: &str) -> Option<u16> {
        endpoint.rsplit(':').next()?.parse().ok()
    }
}
