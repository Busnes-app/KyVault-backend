use std::sync::{LazyLock, OnceLock};

use data_encoding::BASE64;
use tokio::sync::mpsc;

#[cfg(postgresql)]
use crate::{CONFIG, api::WS_USERS};
use crate::{db::models::UserId, util::get_uuid};

/// Unique identifier for this replica process to avoid echoing self-originated PG NOTIFY frames.
pub static INSTANCE_ID: LazyLock<String> = LazyLock::new(get_uuid);

static PUBLISH_TX: OnceLock<mpsc::Sender<String>> = OnceLock::new();

/// Outgoing frames buffered while the listener reconnects; beyond this they are dropped.
#[cfg(postgresql)]
const PUBLISH_QUEUE: usize = 1024;

/// Queues `msg` without blocking or growing past [`PUBLISH_QUEUE`]. Live-sync frames are hints
/// clients recover from on their next sync, so a full queue drops them; a dropped kick is logged,
/// since that session's next request still fails its security-stamp or epoch check.
fn enqueue(kind: &str, msg: String) {
    let Some(tx) = PUBLISH_TX.get() else {
        return;
    };
    if tx.try_send(msg).is_err() {
        if kind == "ws_frame" {
            debug!("PG NOTIFY queue full; dropping ws_frame");
        } else {
            error!("PG NOTIFY queue full; dropping {kind}, other replicas keep their sockets until reconnect");
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgNotifyEnvelope {
    pub origin: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_b64: Option<String>,
}

/// Publishes a raw SignalR/MessagePack binary frame for a user across all replicas.
pub fn publish_ws_frame(user_id: &UserId, payload: &[u8]) {
    if PUBLISH_TX.get().is_none() {
        return;
    }
    let env = PgNotifyEnvelope {
        origin: INSTANCE_ID.clone(),
        kind: "ws_frame".to_owned(),
        user_id: Some(user_id.to_string()),
        tenant_id: None,
        payload_b64: Some(BASE64.encode(payload)),
    };
    if let Ok(json_str) = serde_json::to_string(&env) {
        if json_str.len() <= 7_500 {
            enqueue("ws_frame", json_str);
        } else {
            warn!("Skipping PG NOTIFY ws_frame exceeding 7500 bytes ({} bytes)", json_str.len());
        }
    }
}

/// Publishes an immediate user logout & WebSocket disconnect across all replicas.
pub fn publish_user_logout(user_id: &UserId) {
    let env = PgNotifyEnvelope {
        origin: INSTANCE_ID.clone(),
        kind: "user_logout".to_owned(),
        user_id: Some(user_id.to_string()),
        tenant_id: None,
        payload_b64: None,
    };
    if let Ok(json_str) = serde_json::to_string(&env) {
        enqueue(&env.kind, json_str);
    }
}

pub(crate) fn is_safe_pg_ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Publishes an immediate tenant-wide disconnect across all replicas.
pub fn publish_tenant_kick(tenant_id: &str) {
    let env = PgNotifyEnvelope {
        origin: INSTANCE_ID.clone(),
        kind: "tenant_kick".to_owned(),
        user_id: None,
        tenant_id: Some(tenant_id.to_owned()),
        payload_b64: None,
    };
    if let Ok(json_str) = serde_json::to_string(&env) {
        enqueue(&env.kind, json_str);
    }
}

#[cfg(postgresql)]
fn handle_remote_envelope(payload: &str) {
    let env: PgNotifyEnvelope = match serde_json::from_str(payload) {
        Ok(e) => e,
        Err(e) => {
            warn!("Ignoring malformed PG NOTIFY payload: {e}");
            return;
        }
    };

    if env.origin == *INSTANCE_ID {
        return;
    }

    match env.kind.as_str() {
        "ws_frame" => {
            if let (Some(uid), Some(b64)) = (env.user_id, env.payload_b64) {
                match BASE64.decode(b64.as_bytes()) {
                    Ok(bytes) => WS_USERS.deliver_local_raw(&UserId::from(uid), &bytes),
                    Err(e) => warn!("Invalid base64 in PG NOTIFY ws_frame: {e}"),
                }
            }
        }
        "user_logout" => {
            if let Some(uid) = env.user_id {
                WS_USERS.kick_local_user(&UserId::from(uid));
            }
        }
        "tenant_kick" => {
            if let Some(tid) = env.tenant_id {
                WS_USERS.kick_local_tenant(&tid);
            }
        }
        other => {
            debug!("Ignoring unknown PG NOTIFY kind '{other}'");
        }
    }
}

/// TLS the listener must apply itself, from the libpq `sslmode` and `sslrootcert` options.
#[cfg(postgresql)]
#[derive(Debug, PartialEq, Eq)]
struct ListenerTls {
    verify_ca: bool,
    verify_host: bool,
    root_cert: Option<String>,
}

/// Rewrites a libpq URL into one `tokio_postgres` parses: it accepts only `disable`, `prefer` and
/// `require` and no `sslrootcert`, so `verify-ca` and `verify-full` become `require` and their
/// certificate and hostname checks move into the returned TLS settings.
#[cfg(postgresql)]
fn listener_url(db_url: &str) -> Result<(String, Option<ListenerTls>), String> {
    let mut url = url::Url::parse(db_url).map_err(|e| format!("invalid DATABASE_URL: {e}"))?;
    let (mut mode, mut root_cert) = (None, None);
    let rest: Vec<(String, String)> = url
        .query_pairs()
        .filter_map(|(k, v)| match k.as_ref() {
            "sslmode" => {
                mode = Some(v.into_owned());
                None
            }
            "sslrootcert" => {
                root_cert = Some(v.into_owned());
                None
            }
            _ => Some((k.into_owned(), v.into_owned())),
        })
        .collect();
    let (wire_mode, tls) = match mode.as_deref() {
        None => (None, None),
        Some("disable") => (Some("disable"), None),
        // The listener connects without TLS here, as these modes allow.
        Some("allow" | "prefer") => (Some("prefer"), None),
        Some("require") => (
            Some("require"),
            Some(ListenerTls {
                // libpq verifies a `require` connection only when a root certificate is given.
                verify_ca: root_cert.is_some(),
                verify_host: false,
                root_cert,
            }),
        ),
        Some(m @ ("verify-ca" | "verify-full")) => (
            Some("require"),
            Some(ListenerTls {
                verify_ca: true,
                verify_host: m == "verify-full",
                root_cert,
            }),
        ),
        Some(other) => return Err(format!("unsupported sslmode '{other}' for the LISTEN connection")),
    };
    {
        let mut q = url.query_pairs_mut();
        q.clear();
        q.extend_pairs(&rest);
        if let Some(m) = wire_mode {
            q.append_pair("sslmode", m);
        }
    }
    if url.query() == Some("") {
        url.set_query(None);
    }
    Ok((url.into(), tls))
}

#[cfg(postgresql)]
pub fn start_pg_notify_loop() {
    use std::time::Duration;

    use futures::StreamExt;

    async fn connect_and_listen(db_url: &str, channel: &str, rx: &mut mpsc::Receiver<String>) -> Result<(), String> {
        let (url, tls) = listener_url(db_url)?;
        let (notify_tx, mut notify_rx) = mpsc::unbounded_channel::<String>();

        let client = if let Some(tls) = tls {
            let mut builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
                .map_err(|e| format!("openssl builder error: {e}"))?;
            if !tls.verify_ca {
                builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
            }
            if let Some(ca) = &tls.root_cert {
                builder.set_ca_file(ca).map_err(|e| format!("sslrootcert {ca}: {e}"))?;
            }
            let mut connector = postgres_openssl::MakeTlsConnector::new(builder.build());
            if !tls.verify_host {
                connector.set_callback(|cfg, _| {
                    cfg.set_verify_hostname(false);
                    Ok(())
                });
            }
            let (client, mut connection) =
                tokio_postgres::connect(&url, connector).await.map_err(|e| format!("pg tls connect error: {e}"))?;

            tokio::spawn(async move {
                let mut stream = futures::stream::poll_fn(move |cx| connection.poll_message(cx));
                while let Some(msg) = stream.next().await {
                    match msg {
                        Ok(tokio_postgres::AsyncMessage::Notification(n)) => {
                            drop(notify_tx.send(n.payload().to_owned()));
                        }
                        Ok(_) => {}
                        Err(e) => {
                            warn!("PG TLS listener connection error: {e}");
                            break;
                        }
                    }
                }
            });
            client
        } else {
            let (client, mut connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
                .await
                .map_err(|e| format!("pg connect error: {e}"))?;

            tokio::spawn(async move {
                let mut stream = futures::stream::poll_fn(move |cx| connection.poll_message(cx));
                while let Some(msg) = stream.next().await {
                    match msg {
                        Ok(tokio_postgres::AsyncMessage::Notification(n)) => {
                            drop(notify_tx.send(n.payload().to_owned()));
                        }
                        Ok(_) => {}
                        Err(e) => {
                            warn!("PG listener connection error: {e}");
                            break;
                        }
                    }
                }
            });
            client
        };

        client.batch_execute(&format!("LISTEN \"{channel}\"")).await.map_err(|e| format!("LISTEN failed: {e}"))?;
        info!("PostgreSQL LISTEN/NOTIFY fanout active on channel '{channel}' (instance {})", *INSTANCE_ID);

        loop {
            tokio::select! {
                maybe_payload = notify_rx.recv() => {
                    match maybe_payload {
                        Some(payload) => handle_remote_envelope(&payload),
                        None => return Ok(()),
                    }
                }
                maybe_out = rx.recv() => {
                    match maybe_out {
                        Some(msg) => {
                            if let Err(e) = client
                                .execute("SELECT pg_notify($1, $2)", &[&channel, &msg])
                                .await
                            {
                                return Err(format!("pg_notify failed: {e}"));
                            }
                        }
                        None => return Ok(()),
                    }
                }
            }
        }
    }

    if !CONFIG.tenancy_pg_notify_enabled() {
        return;
    }

    if crate::db::ACTIVE_DB_TYPE.get() != Some(&crate::db::DbConnType::Postgresql) {
        return;
    }

    let channel = CONFIG.tenancy_pg_notify_channel();
    if !is_safe_pg_ident(&channel) {
        error!("Refusing invalid TENANCY_PG_NOTIFY_CHANNEL '{channel}': must match [a-z0-9_]+");
        return;
    }
    let db_url = CONFIG.database_url();

    let (tx, mut rx) = mpsc::channel::<String>(PUBLISH_QUEUE);
    if PUBLISH_TX.set(tx).is_err() {
        return;
    }

    tokio::spawn(async move {
        let mut backoff = Duration::from_millis(500);
        loop {
            match connect_and_listen(&db_url, &channel, &mut rx).await {
                Ok(()) => {
                    warn!("PostgreSQL LISTEN connection closed; reconnecting...");
                    backoff = Duration::from_millis(500);
                }
                Err(e) => {
                    warn!("PostgreSQL LISTEN/NOTIFY loop error: {e}; retrying in {backoff:?}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                }
            }
        }
    });
}

#[cfg(not(postgresql))]
pub fn start_pg_notify_loop() {}

#[cfg(all(test, postgresql))]
mod tests {
    use super::{ListenerTls, listener_url};

    fn check(url: &str) -> (String, Option<ListenerTls>) {
        let (out, tls) = listener_url(url).unwrap();
        out.parse::<tokio_postgres::Config>().unwrap_or_else(|e| panic!("{out}: {e}"));
        (out, tls)
    }

    #[test]
    fn verify_modes_reach_tokio_postgres_with_their_checks() {
        let (out, tls) = check("postgresql://u:p@db:5432/v?sslmode=verify-full&sslrootcert=/ca.pem&connect_timeout=5");
        assert_eq!(out, "postgresql://u:p@db:5432/v?connect_timeout=5&sslmode=require");
        assert_eq!(
            tls,
            Some(ListenerTls {
                verify_ca: true,
                verify_host: true,
                root_cert: Some("/ca.pem".to_owned())
            })
        );
        let (_, tls) = check("postgresql://u:p@db/v?sslmode=verify-ca");
        assert_eq!(tls.map(|t| (t.verify_ca, t.verify_host)), Some((true, false)));
        let (_, tls) = check("postgresql://u:p@db/v?sslmode=require");
        assert_eq!(tls.map(|t| t.verify_ca), Some(false));
        assert_eq!(check("postgresql://u:p@db/v"), ("postgresql://u:p@db/v".to_owned(), None));
        assert!(check("postgresql://u:p@db/v?sslmode=allow").1.is_none());
        assert!(listener_url("postgresql://u:p@db/v?sslmode=bogus").is_err());
    }
}
