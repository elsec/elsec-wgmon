use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// WireGuard re-initiates a handshake after 180 seconds of inactivity.
/// We use the same threshold to detect a silent peer.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(180);

pub async fn wg_quick(action: &str, profile: &str) -> anyhow::Result<()> {
    let output = tokio::process::Command::new("wg-quick")
        .args([action, profile])
        .output()
        .await?;

    if output.status.success() {
        tracing::info!("wg-quick {action} {profile} succeeded");
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);

    if is_idempotent_error(action, &stderr) {
        tracing::debug!("wg-quick {action}: already in target state");
        return Ok(());
    }

    tracing::error!("wg-quick {action} {profile} failed: {stderr}");
    anyhow::bail!("wg-quick {action} {profile} failed: {stderr}")
}

/// Returns the age of the most recent peer handshake, or None if the interface
/// is down or no handshake has occurred yet.
pub async fn latest_handshake_age(profile: &str) -> Option<Duration> {
    let output = tokio::process::Command::new("wg")
        .args(["show", profile, "dump"])
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();

    // `wg show <profile> dump` output:
    //   line 0:  interface  (private_key  public_key  listen_port  fwmark)
    //   line 1+: peers      (public_key  preshared_key  endpoint  allowed_ips  latest_handshake  ...)
    // latest_handshake is a Unix timestamp; 0 means no handshake yet.
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip(1) // skip interface line
        .filter_map(|line| {
            let ts: u64 = line.split('\t').nth(4)?.parse().ok()?;
            if ts == 0 { return None; }
            now.checked_sub(ts).map(Duration::from_secs)
        })
        .min() // most recent handshake across all peers
}

pub fn is_idempotent_error(action: &str, stderr: &str) -> bool {
    (action == "up" && stderr.contains("already exists"))
        || (action == "down" && stderr.contains("is not a WireGuard interface"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn up_already_exists_is_idempotent() {
        assert!(is_idempotent_error("up", "RTNETLINK answers: File exists\nalready exists"));
    }

    #[test]
    fn down_not_wireguard_is_idempotent() {
        assert!(is_idempotent_error("down", "wg-quick: `wg0' is not a WireGuard interface"));
    }

    #[test]
    fn up_real_error_is_not_idempotent() {
        assert!(!is_idempotent_error("up", "wg-quick: line 3: some other error"));
    }

    #[test]
    fn down_real_error_is_not_idempotent() {
        assert!(!is_idempotent_error("down", "wg-quick: some other error"));
    }

    #[test]
    fn action_mismatch_is_not_idempotent() {
        // "already exists" only applies to "up", not "down"
        assert!(!is_idempotent_error("down", "already exists"));
        // "is not a WireGuard interface" only applies to "down", not "up"
        assert!(!is_idempotent_error("up", "is not a WireGuard interface"));
    }

    #[test]
    fn handshake_dump_parsing() {
        // Simulate what latest_handshake_age parses: index 4 is the timestamp.
        // We test the parsing logic directly here.
        let now_secs: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ts = now_secs - 60; // 60 seconds ago

        let dump = format!(
            "privatekey\tpublickey\t51820\toff\n\
             peerpubkey\t(none)\t1.2.3.4:51820\t0.0.0.0/0\t{ts}\t1000\t2000\toff\n"
        );

        let age = dump
            .lines()
            .skip(1)
            .filter_map(|line| {
                let t: u64 = line.split('\t').nth(4)?.parse().ok()?;
                if t == 0 { return None; }
                now_secs.checked_sub(t).map(Duration::from_secs)
            })
            .min();

        let age = age.unwrap();
        assert!(age >= Duration::from_secs(59));
        assert!(age <= Duration::from_secs(61));
    }

    #[test]
    fn handshake_zero_timestamp_ignored() {
        let now_secs: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let dump = "privatekey\tpublickey\t51820\toff\n\
                    peerpubkey\t(none)\t1.2.3.4:51820\t0.0.0.0/0\t0\t0\t0\toff\n";

        let age = dump
            .lines()
            .skip(1)
            .filter_map(|line| {
                let t: u64 = line.split('\t').nth(4)?.parse().ok()?;
                if t == 0 { return None; }
                now_secs.checked_sub(t).map(Duration::from_secs)
            })
            .min();

        assert!(age.is_none());
    }
}
