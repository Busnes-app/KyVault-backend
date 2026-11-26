use chrono::{NaiveDateTime, Utc};
use data_encoding::BASE64URL;
use derive_more::{Display, From};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    api::{ApiResult, EmptyResult},
    crypto,
    db::{
        DbConn, DbConnInner,
        schema::{devices, tenants, users},
    },
    error::MapResult,
    util::{format_date, get_uuid},
};
use macros::{IdFromParam, UuidFromParam};

use super::{AuthRequest, Tenant, User, UserId};

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = devices)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid, user_uuid))]
pub struct Device {
    pub uuid: DeviceId,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,

    pub user_uuid: UserId,

    pub name: String,
    pub atype: i32, // https://github.com/bitwarden/server/blob/8d547dcc280babab70dd4a3c94ced6a34b12dfbf/src/Core/Enums/DeviceType.cs
    pub push_uuid: Option<PushId>,
    pub push_token: Option<String>,

    pub refresh_token: String,
    pub twofactor_remember: Option<String>,
}

/// Local methods
impl Device {
    pub fn new(uuid: DeviceId, user_uuid: UserId, name: String, atype: i32) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid,
            created_at: now,
            updated_at: now,

            user_uuid,
            name,
            atype,

            push_uuid: Some(PushId(get_uuid())),
            push_token: None,
            refresh_token: Device::generate_refresh_token(),
            twofactor_remember: None,
        }
    }

    #[inline(always)]
    pub fn generate_refresh_token() -> String {
        crypto::encode_random_bytes::<64>(&BASE64URL)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "name": self.name,
            "type": self.atype,
            "identifier": self.uuid,
            "creationDate": format_date(&self.created_at),
            "isTrusted": false,
            "object":"device"
        })
    }

    pub fn refresh_twofactor_remember(&mut self) -> String {
        use crate::auth::{encode_jwt, generate_2fa_remember_claims};

        let two_factor_remember_claim = generate_2fa_remember_claims(self.uuid.clone(), self.user_uuid.clone());
        let two_factor_remember_string = encode_jwt(&two_factor_remember_claim);
        self.twofactor_remember = Some(two_factor_remember_string.clone());

        two_factor_remember_string
    }

    pub fn delete_twofactor_remember(&mut self) {
        self.twofactor_remember = None;
    }

    // This rely on the fact we only update the device after a successful login
    pub fn is_new(&self) -> bool {
        self.created_at == self.updated_at
    }

    pub fn is_push_device(&self) -> bool {
        matches!(DeviceType::from_i32(self.atype), DeviceType::Android | DeviceType::Ios)
    }

    pub fn is_cli(&self) -> bool {
        matches!(DeviceType::from_i32(self.atype), DeviceType::WindowsCLI | DeviceType::MacOsCLI | DeviceType::LinuxCLI)
    }

    pub fn is_mobile(&self) -> bool {
        matches!(DeviceType::from_i32(self.atype), DeviceType::Android | DeviceType::Ios)
    }
}

pub struct DeviceWithAuthRequest {
    pub device: Device,
    pub pending_auth_request: Option<AuthRequest>,
}

impl DeviceWithAuthRequest {
    pub fn to_json(&self) -> Value {
        let auth_request = match &self.pending_auth_request {
            Some(auth_request) => auth_request.to_json_for_pending_device(),
            None => Value::Null,
        };
        json!({
            "id": self.device.uuid,
            "name": self.device.name,
            "type": self.device.atype,
            "identifier": self.device.uuid,
            "creationDate": format_date(&self.device.created_at),
            "devicePendingAuthRequest": auth_request,
            "isTrusted": false,
            "encryptedPublicKey": null,
            "encryptedUserKey": null,
            "object": "device",
        })
    }

    pub fn from(c: Device, a: Option<AuthRequest>) -> Self {
        Self {
            device: c,
            pending_auth_request: a,
        }
    }
}

/// Database methods
impl Device {
    pub async fn save(&mut self, update_time: bool, conn: &DbConn) -> EmptyResult {
        if update_time {
            self.updated_at = Utc::now().naive_utc();
        }

        db_run! { conn:
            mysql {
                crate::util::retry(||
                    diesel::insert_into(devices::table)
                        .values(&*self)
                        .on_conflict(diesel::dsl::DuplicatedKeys)
                        .do_update()
                        .set(&*self)
                        .execute(conn),
                    10,
                ).map_res("Error saving device")
            }
            postgresql, sqlite {
                crate::util::retry(||
                    diesel::insert_into(devices::table)
                        .values(&*self)
                        .on_conflict((devices::uuid, devices::user_uuid))
                        .do_update()
                        .set(&*self)
                        .execute(conn),
                    10,
                ).map_res("Error saving device")
            }
        }
    }

    /// Atomically validates a refresh token against the live `users`, `tenants`, and `devices`
    /// rows and updates only `devices.updated_at`.
    ///
    /// Locks `users` (`FOR SHARE` on PostgreSQL) before updating `devices` to match the global
    /// `tenants -> users -> devices` lock order, serializing cleanly with `fence_user` /
    /// `sync_user` / `erase_user` so a concurrent revocation can neither be undone nor paired
    /// with a post-revocation `security_stamp`.
    #[allow(clippy::too_many_arguments)]
    pub fn load_and_touch_for_refresh_tx(
        conn: &mut DbConnInner,
        device_token: &str,
        expected_tid: Option<&str>,
        now: NaiveDateTime,
        multi_tenant: bool,
        served_cells: &[String],
        now_ts: i64,
        max_authority_age_secs: i64,
    ) -> ApiResult<(Self, User)> {
        conn.transaction(|conn| {
            let Some((device_uuid, user_uuid)): Option<(DeviceId, UserId)> = devices::table
                .filter(devices::refresh_token.eq(device_token))
                .select((devices::uuid, devices::user_uuid))
                .first(conn)
                .optional()
                .map_res("Error loading device")?
            else {
                err!("Invalid refresh token");
            };

            let Some(user) = lock_user_for_share(conn, &user_uuid).map_res("Error loading user")? else {
                err!("Impossible to find user");
            };
            if !user.enabled {
                err_code!("User is disabled", 403);
            }
            if multi_tenant {
                let tid = crate::tenancy::require_user_tenant(&user)?;
                if expected_tid != Some(tid) {
                    err_code!("Refresh token tenant mismatch", 403);
                }
                let Some(tenant) =
                    tenants::table.find(tid).first::<Tenant>(conn).optional().map_res("Error loading tenant")?
                else {
                    err_code!("Tenant not found or not provisioned in this cell", 403);
                };
                crate::tenancy::check_tenant_active_for_cells(&tenant, served_cells, now_ts, max_authority_age_secs)?;
            }

            let updated: usize = diesel::update(
                devices::table
                    .filter(devices::uuid.eq(&device_uuid))
                    .filter(devices::user_uuid.eq(&user_uuid))
                    .filter(devices::refresh_token.eq(device_token)),
            )
            .set(devices::updated_at.eq(now))
            .execute(conn)
            .map_res("Error updating device")?;
            if updated == 0 {
                err!("Invalid refresh token");
            }

            let Some(device) = devices::table
                .filter(devices::uuid.eq(&device_uuid))
                .filter(devices::user_uuid.eq(&user_uuid))
                .first::<Self>(conn)
                .optional()
                .map_res("Error loading device")?
            else {
                err!("Invalid refresh token");
            };
            Ok((device, user))
        })
    }

    pub async fn load_and_touch_for_refresh(
        device_token: &str,
        expected_tid: Option<&str>,
        conn: &DbConn,
    ) -> ApiResult<(Self, User)> {
        let token = device_token.to_owned();
        let expected_tid = expected_tid.map(ToOwned::to_owned);
        let now = Utc::now().naive_utc();
        let now_ts = Utc::now().timestamp();
        let multi_tenant = crate::CONFIG.is_multi_tenant();
        let served_cells = crate::CONFIG.served_cells();
        let max_authority_age_secs = crate::CONFIG.tenancy_authority_max_age_secs();
        conn.run(move |conn| {
            Self::load_and_touch_for_refresh_tx(
                conn,
                &token,
                expected_tid.as_deref(),
                now,
                multi_tenant,
                &served_cells,
                now_ts,
                max_authority_age_secs,
            )
        })
        .await
    }

    /// Touches `updated_at` (and optionally persists `twofactor_remember`) for an existing
    /// device only if its `refresh_token` is still unchanged. Never overwrites `refresh_token`
    /// and never resurrects a deleted device.
    pub fn touch_authenticated_tx(
        conn: &mut DbConnInner,
        device: &Self,
        now: NaiveDateTime,
        update_twofactor_remember: bool,
    ) -> EmptyResult {
        let updated: usize = if update_twofactor_remember {
            diesel::update(
                devices::table
                    .filter(devices::uuid.eq(&device.uuid))
                    .filter(devices::user_uuid.eq(&device.user_uuid))
                    .filter(devices::refresh_token.eq(&device.refresh_token)),
            )
            .set((devices::updated_at.eq(now), devices::twofactor_remember.eq(&device.twofactor_remember)))
            .execute(conn)
            .map_res("Error saving device")?
        } else {
            diesel::update(
                devices::table
                    .filter(devices::uuid.eq(&device.uuid))
                    .filter(devices::user_uuid.eq(&device.user_uuid))
                    .filter(devices::refresh_token.eq(&device.refresh_token)),
            )
            .set(devices::updated_at.eq(now))
            .execute(conn)
            .map_res("Error saving device")?
        };
        if updated == 0 {
            err_code!("Device session was revoked during login", 401);
        }
        Ok(())
    }

    pub async fn touch_authenticated(&mut self, update_twofactor_remember: bool, conn: &DbConn) -> EmptyResult {
        let now = Utc::now().naive_utc();
        self.updated_at = now;
        let device = &*self;
        conn.run(move |conn| Self::touch_authenticated_tx(conn, device, now, update_twofactor_remember)).await
    }

    /// Updates only `push_token` and `updated_at` without touching `refresh_token` or
    /// `twofactor_remember`.
    pub async fn update_push_token(&mut self, token: String, conn: &DbConn) -> EmptyResult {
        let now = Utc::now().naive_utc();
        self.push_token = Some(token);
        self.updated_at = now;
        let uuid = self.uuid.clone();
        let user_uuid = self.user_uuid.clone();
        let push_token = self.push_token.clone();
        conn.run(move |conn| {
            let updated: usize = diesel::update(
                devices::table.filter(devices::uuid.eq(&uuid)).filter(devices::user_uuid.eq(&user_uuid)),
            )
            .set((devices::push_token.eq(&push_token), devices::updated_at.eq(now)))
            .execute(conn)
            .map_res("Error saving device push token")?;
            if updated == 0 {
                err_code!("Device not found", 404);
            }
            Ok(())
        })
        .await
    }

    /// Updates only `push_uuid` and `updated_at` without touching `refresh_token` or
    /// `twofactor_remember`.
    pub async fn update_push_uuid(&mut self, conn: &DbConn) -> EmptyResult {
        let now = Utc::now().naive_utc();
        self.updated_at = now;
        let uuid = self.uuid.clone();
        let user_uuid = self.user_uuid.clone();
        let push_uuid = self.push_uuid.clone();
        conn.run(move |conn| {
            let updated: usize = diesel::update(
                devices::table.filter(devices::uuid.eq(&uuid)).filter(devices::user_uuid.eq(&user_uuid)),
            )
            .set((devices::push_uuid.eq(&push_uuid), devices::updated_at.eq(now)))
            .execute(conn)
            .map_res("Error saving device push uuid")?;
            if updated == 0 {
                err_code!("Device not found", 404);
            }
            Ok(())
        })
        .await
    }

    /// Clears `twofactor_remember` and updates `updated_at` without touching `refresh_token`.
    pub async fn clear_twofactor_remember(&mut self, conn: &DbConn) -> EmptyResult {
        let now = Utc::now().naive_utc();
        self.twofactor_remember = None;
        self.updated_at = now;
        let uuid = self.uuid.clone();
        let user_uuid = self.user_uuid.clone();
        conn.run(move |conn| {
            diesel::update(devices::table.filter(devices::uuid.eq(&uuid)).filter(devices::user_uuid.eq(&user_uuid)))
                .set((devices::twofactor_remember.eq::<Option<String>>(None), devices::updated_at.eq(now)))
                .execute(conn)
                .map_res("Error clearing device twofactor remember")
        })
        .await
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(devices::table.filter(devices::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error removing devices for user")
        })
        .await
    }

    pub async fn find_by_uuid_and_user(uuid: &DeviceId, user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            devices::table
                .filter(devices::uuid.eq(uuid))
                .filter(devices::user_uuid.eq(user_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_with_auth_request_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<DeviceWithAuthRequest> {
        let devices = Self::find_by_user(user_uuid, conn).await;
        let mut result = Vec::new();
        for device in devices {
            let auth_request = AuthRequest::find_by_user_and_requested_device(user_uuid, &device.uuid, conn).await;
            result.push(DeviceWithAuthRequest::from(device, auth_request));
        }
        result
    }

    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            devices::table.filter(devices::user_uuid.eq(user_uuid)).load::<Self>(conn).expect("Error loading devices")
        })
        .await
    }

    pub async fn find_by_uuid(uuid: &DeviceId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| devices::table.filter(devices::uuid.eq(uuid)).first::<Self>(conn).ok()).await
    }

    pub async fn clear_push_token_by_uuid(uuid: &DeviceId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::update(devices::table)
                .filter(devices::uuid.eq(uuid))
                .set(devices::push_token.eq::<Option<String>>(None))
                .execute(conn)
                .map_res("Error removing push token")
        })
        .await
    }
    pub async fn find_by_refresh_token(refresh_token: &str, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| devices::table.filter(devices::refresh_token.eq(refresh_token)).first::<Self>(conn).ok())
            .await
    }

    pub async fn find_latest_active_by_user(user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .order(devices::updated_at.desc())
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_push_devices_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .filter(devices::push_token.is_not_null())
                .load::<Self>(conn)
                .expect("Error loading push devices")
        })
        .await
    }

    pub async fn check_user_has_push_device(user_uuid: &UserId, conn: &DbConn) -> bool {
        conn.run(move |conn| {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .filter(devices::push_token.is_not_null())
                .count()
                .first::<i64>(conn)
                .ok()
                .unwrap_or(0)
                != 0
        })
        .await
    }

    pub async fn rotate_refresh_tokens_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        // Generate a new token per device without upserting so deleted devices are never resurrected.
        let user_uuid = user_uuid.clone();
        conn.run(move |conn| {
            let device_uuids: Vec<DeviceId> = devices::table
                .filter(devices::user_uuid.eq(&user_uuid))
                .select(devices::uuid)
                .load(conn)
                .map_res("Error loading devices for token rotation")?;
            for device_uuid in device_uuids {
                diesel::update(
                    devices::table.filter(devices::uuid.eq(&device_uuid)).filter(devices::user_uuid.eq(&user_uuid)),
                )
                .set((
                    devices::refresh_token.eq(Self::generate_refresh_token()),
                    devices::twofactor_remember.eq::<Option<String>>(None),
                ))
                .execute(conn)
                .map(drop)
                .map_res("Error rotating device refresh token")?;
            }
            Ok(())
        })
        .await
    }

    pub async fn clear_twofactor_remember_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::update(devices::table)
                .filter(devices::user_uuid.eq(user_uuid))
                .set(devices::twofactor_remember.eq::<Option<String>>(None))
                .execute(conn)
                .map_res("Error removing two factor remember tokens")
        })
        .await
    }
}

fn lock_user_for_share(conn: &mut DbConnInner, uid: &UserId) -> QueryResult<Option<User>> {
    match conn {
        #[cfg(postgresql)]
        DbConnInner::Postgresql(pg) => users::table.find(uid).for_share().first::<User>(pg).optional(),
        #[allow(unreachable_patterns, reason = "only reachable when another backend is compiled in")]
        _ => users::table.find(uid).first::<User>(conn).optional(),
    }
}

#[derive(Display)]
pub enum DeviceType {
    #[display("Android")]
    Android = 0,
    #[display("iOS")]
    Ios = 1,
    #[display("Chrome Extension")]
    ChromeExtension = 2,
    #[display("Firefox Extension")]
    FirefoxExtension = 3,
    #[display("Opera Extension")]
    OperaExtension = 4,
    #[display("Edge Extension")]
    EdgeExtension = 5,
    #[display("Windows")]
    WindowsDesktop = 6,
    #[display("macOS")]
    MacOsDesktop = 7,
    #[display("Linux")]
    LinuxDesktop = 8,
    #[display("Chrome")]
    ChromeBrowser = 9,
    #[display("Firefox")]
    FirefoxBrowser = 10,
    #[display("Opera")]
    OperaBrowser = 11,
    #[display("Edge")]
    EdgeBrowser = 12,
    #[display("Internet Explorer")]
    IEBrowser = 13,
    #[display("Unknown Browser")]
    UnknownBrowser = 14,
    #[display("Android")]
    AndroidAmazon = 15,
    #[display("UWP")]
    Uwp = 16,
    #[display("Safari")]
    SafariBrowser = 17,
    #[display("Vivaldi")]
    VivaldiBrowser = 18,
    #[display("Vivaldi Extension")]
    VivaldiExtension = 19,
    #[display("Safari Extension")]
    SafariExtension = 20,
    #[display("SDK")]
    Sdk = 21,
    #[display("Server")]
    Server = 22,
    #[display("Windows CLI")]
    WindowsCLI = 23,
    #[display("macOS CLI")]
    MacOsCLI = 24,
    #[display("Linux CLI")]
    LinuxCLI = 25,
    #[display("DuckDuckGo")]
    DuckDuckGoBrowser = 26,
}

impl DeviceType {
    #[expect(clippy::match_same_arms, reason = "Specifically define 14 and have a fallback for new types")]
    pub fn from_i32(value: i32) -> DeviceType {
        match value {
            0 => DeviceType::Android,
            1 => DeviceType::Ios,
            2 => DeviceType::ChromeExtension,
            3 => DeviceType::FirefoxExtension,
            4 => DeviceType::OperaExtension,
            5 => DeviceType::EdgeExtension,
            6 => DeviceType::WindowsDesktop,
            7 => DeviceType::MacOsDesktop,
            8 => DeviceType::LinuxDesktop,
            9 => DeviceType::ChromeBrowser,
            10 => DeviceType::FirefoxBrowser,
            11 => DeviceType::OperaBrowser,
            12 => DeviceType::EdgeBrowser,
            13 => DeviceType::IEBrowser,
            14 => DeviceType::UnknownBrowser,
            15 => DeviceType::AndroidAmazon,
            16 => DeviceType::Uwp,
            17 => DeviceType::SafariBrowser,
            18 => DeviceType::VivaldiBrowser,
            19 => DeviceType::VivaldiExtension,
            20 => DeviceType::SafariExtension,
            21 => DeviceType::Sdk,
            22 => DeviceType::Server,
            23 => DeviceType::WindowsCLI,
            24 => DeviceType::MacOsCLI,
            25 => DeviceType::LinuxCLI,
            26 => DeviceType::DuckDuckGoBrowser,
            _ => DeviceType::UnknownBrowser,
        }
    }
}

#[derive(
    Clone, Debug, DieselNewType, Display, From, FromForm, Hash, PartialEq, Eq, Serialize, Deserialize, IdFromParam,
)]
pub struct DeviceId(String);

#[derive(Clone, Debug, DieselNewType, Display, From, FromForm, Serialize, Deserialize, UuidFromParam)]
pub struct PushId(pub String);
