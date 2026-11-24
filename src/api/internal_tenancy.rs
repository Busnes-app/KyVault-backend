//! Private, versioned management API for the suite worker: `/internal/tenancy/v1/*`.
//!
//! Only exists in multi-tenant mode and only for the pre-provisioned bearer secret. Never route
//! it through the public proxy. Business logic lives in `crate::tenancy::ops`.

use chrono::Utc;
use rocket::{
    Request, Route,
    http::Status,
    request::{FromRequest, Outcome},
    serde::json::{Json, Value},
};

use crate::{
    CONFIG,
    api::{ApiResult, WS_USERS},
    crypto::ct_eq,
    db::DbConn,
    tenancy::{
        ops::{self, Kicks},
        pubsub,
    },
};

const MIN_SECRET_LEN: usize = 32;

pub fn routes() -> Vec<Route> {
    routes![
        health,
        reconcile_orgs,
        logout_user,
        sync_user,
        erase_user,
        purge_begin,
        cleanup_pending,
        cleanup_complete,
        storage_prepare,
        storage_apply,
        storage_repair_seq,
    ]
}

/// Request guard for every internal route.
pub struct InternalTenancyAuth;

fn authorize(multi_tenant: bool, secret: Option<&str>, authorization: Option<&str>) -> Result<(), Status> {
    if !multi_tenant {
        return Err(Status::NotFound);
    }
    let secret = secret.map(str::trim).filter(|s| s.len() >= MIN_SECRET_LEN).ok_or(Status::ServiceUnavailable)?;
    let token = authorization.and_then(|h| h.strip_prefix("Bearer ")).ok_or(Status::Unauthorized)?;
    if ct_eq(token.trim(), secret) {
        Ok(())
    } else {
        Err(Status::Unauthorized)
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for InternalTenancyAuth {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let secret = CONFIG.tenancy_internal_api_secret();
        match authorize(CONFIG.is_multi_tenant(), secret.as_deref(), request.headers().get_one("Authorization")) {
            Ok(()) => Outcome::Success(Self),
            Err(status) => Outcome::Error((status, ())),
        }
    }
}

/// Disconnects after the transaction committed, locally and on every replica.
fn deliver(kicks: Kicks) {
    for uid in kicks.users {
        WS_USERS.kick_local_user(&uid);
        pubsub::publish_user_logout(&uid);
    }
    for tid in kicks.tenants {
        WS_USERS.kick_local_tenant(&tid);
        pubsub::publish_tenant_kick(&tid);
    }
}

fn now() -> i64 {
    Utc::now().timestamp()
}

#[get("/health")]
fn health(_auth: InternalTenancyAuth) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "multi_tenant": CONFIG.is_multi_tenant(),
        "home_region": CONFIG.home_region(),
    }))
}

#[post("/orgs/reconcile", data = "<data>")]
async fn reconcile_orgs(
    _auth: InternalTenancyAuth,
    conn: DbConn,
    data: Json<ops::ReconcileRequest>,
) -> ApiResult<Json<ops::ReconcileResponse>> {
    let region = CONFIG.home_region();
    let (resp, kicks) = conn.run(move |c| ops::reconcile_orgs(c, &data, &region, now())).await?;
    deliver(kicks);
    Ok(Json(resp))
}

#[post("/users/logout", data = "<data>")]
async fn logout_user(
    _auth: InternalTenancyAuth,
    conn: DbConn,
    data: Json<ops::LogoutRequest>,
) -> ApiResult<Json<ops::LogoutResponse>> {
    let (resp, kicks) = conn.run(move |c| ops::logout_user(c, &data, now())).await?;
    deliver(kicks);
    Ok(Json(resp))
}

#[post("/users/sync", data = "<data>")]
async fn sync_user(
    _auth: InternalTenancyAuth,
    conn: DbConn,
    data: Json<ops::SyncRequest>,
) -> ApiResult<Json<ops::UserStatusResponse>> {
    let (resp, kicks) = conn.run(move |c| ops::sync_user(c, &data, now())).await?;
    deliver(kicks);
    Ok(Json(resp))
}

#[post("/users/erase", data = "<data>")]
async fn erase_user(
    _auth: InternalTenancyAuth,
    conn: DbConn,
    data: Json<ops::EraseRequest>,
) -> ApiResult<Json<ops::EraseResponse>> {
    let (resp, kicks) = conn.run(move |c| ops::erase_user(c, &data, now())).await?;
    deliver(kicks);
    Ok(Json(resp))
}

#[post("/tenants/<tenant_id>/purge/begin")]
async fn purge_begin(_auth: InternalTenancyAuth, conn: DbConn, tenant_id: &str) -> ApiResult<Json<ops::PurgeResponse>> {
    let tid = tenant_id.to_owned();
    let authority = CONFIG.sso_authority();
    let (resp, kicks) = conn.run(move |c| ops::purge_begin(c, &tid, &authority, now())).await?;
    deliver(kicks);
    Ok(Json(resp))
}

#[get("/cleanup/pending?<limit>")]
async fn cleanup_pending(
    _auth: InternalTenancyAuth,
    conn: DbConn,
    limit: Option<i64>,
) -> ApiResult<Json<ops::PendingResponse>> {
    Ok(Json(conn.run(move |c| ops::cleanup_pending(c, limit)).await?))
}

#[post("/cleanup/complete", data = "<data>")]
async fn cleanup_complete(
    _auth: InternalTenancyAuth,
    conn: DbConn,
    data: Json<ops::CompleteRequest>,
) -> ApiResult<Json<ops::CompleteResponse>> {
    Ok(Json(conn.run(move |c| ops::cleanup_complete(c, &data, now())).await?))
}

#[post("/storage/prepare", data = "<data>")]
async fn storage_prepare(
    _auth: InternalTenancyAuth,
    conn: DbConn,
    data: Json<ops::PrepareRequest>,
) -> ApiResult<Json<ops::PrepareResponse>> {
    let region = CONFIG.home_region();
    Ok(Json(conn.run(move |c| ops::storage_prepare(c, &data, &region)).await?))
}

#[post("/storage/apply", data = "<data>")]
async fn storage_apply(
    _auth: InternalTenancyAuth,
    conn: DbConn,
    data: Json<ops::ApplyRequest>,
) -> ApiResult<Json<ops::ApplyResponse>> {
    Ok(Json(conn.run(move |c| ops::storage_apply(c, &data, now())).await?))
}

#[post("/storage/repair-seq", data = "<data>")]
async fn storage_repair_seq(
    _auth: InternalTenancyAuth,
    conn: DbConn,
    data: Json<ops::RepairSeqRequest>,
) -> ApiResult<Json<ops::RepairSeqResponse>> {
    Ok(Json(conn.run(move |c| ops::storage_repair_seq(c, &data)).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn single_tenant_hides_routes() {
        assert_eq!(authorize(false, Some(SECRET), Some(&format!("Bearer {SECRET}"))), Err(Status::NotFound));
    }

    #[test]
    fn missing_or_short_secret_is_unavailable() {
        let header = format!("Bearer {SECRET}");
        assert_eq!(authorize(true, None, Some(&header)), Err(Status::ServiceUnavailable));
        assert_eq!(authorize(true, Some("short"), Some("Bearer short")), Err(Status::ServiceUnavailable));
        assert_eq!(authorize(true, Some("   "), Some("Bearer ")), Err(Status::ServiceUnavailable));
    }

    #[test]
    fn bearer_token_must_match() {
        assert_eq!(authorize(true, Some(SECRET), None), Err(Status::Unauthorized));
        assert_eq!(authorize(true, Some(SECRET), Some(SECRET)), Err(Status::Unauthorized));
        assert_eq!(authorize(true, Some(SECRET), Some(&format!("Basic {SECRET}"))), Err(Status::Unauthorized));
        assert_eq!(authorize(true, Some(SECRET), Some(&format!("Bearer {SECRET}x"))), Err(Status::Unauthorized));
        assert_eq!(authorize(true, Some(SECRET), Some("Bearer ")), Err(Status::Unauthorized));
        assert_eq!(authorize(true, Some(SECRET), Some(&format!("Bearer {SECRET}"))), Ok(()));
    }
}
