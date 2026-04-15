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

    // Ignore already-up / already-down errors
    if action == "up" && stderr.contains("already exists") {
        tracing::debug!("wg-quick up: interface already up");
        return Ok(());
    }
    if action == "down" && stderr.contains("is not a WireGuard interface") {
        tracing::debug!("wg-quick down: interface already down");
        return Ok(());
    }

    tracing::error!("wg-quick {action} {profile} failed: {stderr}");
    Ok(()) // log but don't crash — keep watching
}
