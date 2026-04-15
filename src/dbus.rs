use futures_util::StreamExt;
use std::pin::Pin;
use zbus::{
    fdo::ObjectManagerProxy,
    message::Type as MessageType,
    proxy,
    zvariant::OwnedObjectPath,
    Connection, MatchRule, MessageStream,
};
use std::collections::HashMap;
use zbus::zvariant::OwnedValue;

#[proxy(
    interface = "net.connman.iwd.Station",
    default_service = "net.connman.iwd"
)]
trait Station {
    #[zbus(property)]
    fn state(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn connected_network(&self) -> zbus::Result<OwnedObjectPath>;
}

#[proxy(
    interface = "net.connman.iwd.Network",
    default_service = "net.connman.iwd"
)]
trait Network {
    #[zbus(property)]
    fn name(&self) -> zbus::Result<String>;
}

pub async fn get_connected_ssids(conn: &Connection) -> anyhow::Result<Vec<String>> {
    let obj_manager = ObjectManagerProxy::builder(conn)
        .destination("net.connman.iwd")?
        .path("/")?
        .build()
        .await?;

    let objects = obj_manager.get_managed_objects().await?;

    let mut ssids = Vec::new();

    for (path, ifaces) in &objects {
        if !ifaces.contains_key("net.connman.iwd.Station") {
            continue;
        }

        let station = StationProxy::builder(conn)
            .path(path.clone())?
            .build()
            .await?;

        let state = match station.state().await {
            Ok(s) => s,
            Err(_) => continue,
        };

        if state != "connected" {
            continue;
        }

        let net_path = match station.connected_network().await {
            Ok(p) => p,
            Err(_) => continue,
        };

        if let Ok(network) = NetworkProxy::builder(conn)
            .path(net_path)?
            .build()
            .await
        {
            if let Ok(name) = network.name().await {
                ssids.push(name);
            }
        }
    }

    Ok(ssids)
}

/// Returns a stream that yields () whenever an iwd Station property changes.
pub async fn watch_station_changes(
    conn: &Connection,
) -> anyhow::Result<Pin<Box<dyn futures_util::Stream<Item = ()> + '_>>> {
    let rule = MatchRule::builder()
        .msg_type(MessageType::Signal)
        .sender("net.connman.iwd")?
        .interface("org.freedesktop.DBus.Properties")?
        .member("PropertiesChanged")?
        .build();

    let stream = MessageStream::for_match_rule(rule, conn, None).await?;

    let filtered = stream.filter_map(|msg| async move {
        let msg = msg.ok()?;
        let body = msg.body();
        let (iface, changed, _invalidated): (
            &str,
            HashMap<&str, OwnedValue>,
            Vec<&str>,
        ) = body.deserialize().ok()?;

        if iface != "net.connman.iwd.Station" {
            return None;
        }

        if changed.contains_key("State") || changed.contains_key("ConnectedNetwork") {
            Some(())
        } else {
            None
        }
    });

    Ok(Box::pin(filtered))
}
