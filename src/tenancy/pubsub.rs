use std::sync::{LazyLock, OnceLock};

use data_encoding::BASE64;
use tokio::sync::mpsc;

#[cfg(postgresql)]
use crate::{CONFIG, api::WS_USERS};
use crate::{db::models::UserId, util::get_uuid};

/// Unique identifier for this replica process to avoid echoing self-originated PG NOTIFY frames.
pub static INSTANCE_ID: LazyLock<String> = LazyLock::new(get_uuid);

static PUBLISH_TX: OnceLock<mpsc::UnboundedSender<String>> = OnceLock::new();

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
    let Some(tx) = PUBLISH_TX.get() else {
        return;
    };
    let env = PgNotifyEnvelope {
        origin: INSTANCE_ID.clone(),
        kind: "ws_frame".to_owned(),
        user_id: Some(user_id.to_string()),
        tenant_id: None,
        payload_b64: Some(BASE64.encode(payload)),
    };
    if let Ok(json_str) = serde_json::to_string(&env) {
        if json_str.len() <= 7_500 {
            drop(tx.send(json_str));
        } else {
            warn!("Skipping PG NOTIFY ws_frame exceeding 7500 bytes ({} bytes)", json_str.len());
        }
    }
}

/// Publishes an immediate user logout & WebSocket disconnect across all replicas.
pub fn publish_user_logout(user_id: &UserId) {
    let Some(tx) = PUBLISH_TX.get() else {
        return;
    };
    let env = PgNotifyEnvelope {
        origin: INSTANCE_ID.clone(),
        kind: "user_logout".to_owned(),
        user_id: Some(user_id.to_string()),
        tenant_id: None,
        payload_b64: None,
    };
    if let Ok(json_str) = serde_json::to_string(&env) {
        drop(tx.send(json_str));
    }
}

pub(crate) fn is_safe_pg_ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Publishes an immediate tenant-wide disconnect across all replicas.
pub fn publish_tenant_kick(tenant_id: &str) {
    let Some(tx) = PUBLISH_TX.get() else {
        return;
    };
    let env = PgNotifyEnvelope {
        origin: INSTANCE_ID.clone(),
        kind: "tenant_kick".to_owned(),
        user_id: None,
        tenant_id: Some(tenant_id.to_owned()),
        payload_b64: None,
    };
    if let Ok(json_str) = serde_json::to_string(&env) {
        drop(tx.send(json_str));
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

#[cfg(postgresql)]
pub fn start_pg_notify_loop() {
    use std::time::Duration;

    use futures::StreamExt;

    async fn connect_and_listen(
        db_url: &str,
        channel: &str,
        rx: &mut mpsc::UnboundedReceiver<String>,
    ) -> Result<(), String> {
        let use_tls = db_url.contains("sslmode=require")
            || db_url.contains("sslmode=verify-ca")
            || db_url.contains("sslmode=verify-full");

        let (notify_tx, mut notify_rx) = mpsc::unbounded_channel::<String>();

        let client = if use_tls {
            let mut builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
                .map_err(|e| format!("openssl builder error: {e}"))?;
            if db_url.contains("sslmode=require") {
                builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
            }
            let connector = postgres_openssl::MakeTlsConnector::new(builder.build());
            let (client, mut connection) =
                tokio_postgres::connect(db_url, connector).await.map_err(|e| format!("pg tls connect error: {e}"))?;

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
            let (client, mut connection) = tokio_postgres::connect(db_url, tokio_postgres::NoTls)
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

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
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
