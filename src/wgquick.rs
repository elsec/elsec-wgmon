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
    Ok(()) // log but don't crash — keep watching
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
}
