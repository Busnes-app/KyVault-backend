# KyVault Multi-Tenant Architecture & Operations Guide

`Busnes-app/KyVault-backend` is a focused AGPL-3.0-only fork of Vaultwarden (`1.37.5`) implementing hosted multi-tenant isolation, zero-knowledge Recovery Kit & Organization Admin Escrow, hardened import/quota guardrails, PostgreSQL `LISTEN`/`NOTIFY` multi-replica WebSocket fanout, and the Go suite worker (`worker/`).

All single-tenant / self-hosted Vaultwarden behavior remains unchanged when `MULTI_TENANT_ENABLED=false` (the default).

## Architecture

1. **Rust Vaultwarden Backend (`src/`)**
   - **Strict Tenant Isolation**: Every user, organization, cipher, attachment, send, SSO link, and recovery bundle is bound to a KyIdentity `tenant_id` (`tenants.id`). Cross-tenant reads, invites, cipher sharing, emergency access, and WebSocket subscriptions are denied server-side.
   - **Fail-Closed Startup Guardrails**: When `MULTI_TENANT_ENABLED=true`, startup refuses to boot unless `SSO_ENABLED=true`, `SSO_ONLY=true`, `SIGNUPS_ALLOWED=false`, `INVITATIONS_ALLOWED=false`, `ENABLE_WEBSOCKET=true`, `ADMIN_TOKEN` is unset, `TENANCY_HOME_REGION` is set, and PostgreSQL is active.
   - **Tenant Lifecycle & Export-Only Billing Hold**:
     - `active` + `app_enabled=true`: Full access.
     - `suspended` / `app_enabled=false` / `erasing` / `deleted`: Login, refresh, and API access denied (`403`), active WebSockets disconnected across all replicas via PostgreSQL `NOTIFY`.
     - `billing_state=export_only`: Mutations blocked (`403`) while read/export routes (`/api/sync`, `/api/ciphers/*/attachment/*`, `/api/organizations/*/export`, `/api/tenancy/*`) remain accessible.
   - **Zero-Knowledge Recovery Kit & Org Admin Escrow (`/api/tenancy/recovery/*`)**:
     - `GET/PUT/DELETE /api/tenancy/recovery/personal` — stores an opaque client-wrapped `UserKey` blob (encrypted with a random 256-bit Recovery Kit secret; server never sees plaintext).
     - `GET/PUT/DELETE /api/tenancy/recovery/escrow/<org_id>` — allows a tenant member to opt into Organization Admin Escrow (client wraps `UserKey` to the organization's public key).
     - `GET /api/tenancy/recovery/escrow/<org_id>/<target_user_id>` — allows a same-tenant Organization Owner/Admin to retrieve the wrapped escrow blob for an enrolled member with audit logging.
   - **Import Guardrails & Quotas**:
     - `POST /api/ciphers/import` and `POST /api/organizations/<org_id>/import` enforce `TENANCY_MAX_IMPORT_CIPHERS` (default `5000`), `TENANCY_MAX_IMPORT_FOLDERS` (default `500`), per-tenant `max_ciphers` quota (`tenants.quotas_json`), and per-tenant storage pool quotas (`tenants.storage_pool_bytes` / `storage_over_since`).
   - **Multi-Replica WebSocket Fanout (PostgreSQL `LISTEN`/`NOTIFY`)**:
     - No Redis dependency. Local WebSocket notifications, `user_logout`, and `tenant_kick` events publish JSON envelopes over `TENANCY_PG_NOTIFY_CHANNEL` (`kyvault_notify`) so every Rust replica fans out updates and disconnects revoked users/tenants immediately.

2. **Go Suite Worker (`worker/`)**
   - Reuses `github.com/Busnes-app/ky-primitives` (`oidcverify`, `syncauth`, `scim`).
   - **HTTP Endpoints**:
     - `GET /healthz` — verifies PostgreSQL pool health.
     - `POST /api/sync/events` — verifies `X-KySignOn-Signature` (`syncauth.Verify`), deduplicates `event_id` in `tenant_processed_events`, and handles `user.created`, `user.updated`, `user.deleted`, `user.erased`, `tenant.updated`, `tenant.suspended`, `tenant.erased`.
     - `POST /api/oidc/backchannel-logout` — verifies `logout_token` RS256 signature & claims via `oidcverify.Verifier.VerifyLogout`, enforces durable JTI replay prevention in `tenant_processed_events`, rotates `users.security_stamp`, clears `devices.refresh_token`, and emits PostgreSQL `NOTIFY user_logout`.
   - **Background Loops**:
     - **Org Entitlement Sync (`GET /api/suite/orgs`)**: Filters by `HOME_REGION`, enforces monotonic `revision`, never resurrects `erasing`/`deleted` tombstones, and fences + broadcasts `tenant_kick` on suspension/disable.
     - **Erasure Polling (`GET /api/suite/erased`)**: Durable cursor in `tenant_sync_cursors`, retries any tenant stuck in `erasing`, deletes tenant S3/local files under `tenants/<tenant_id>/` BEFORE purging DB rows across all 32 tables, and retains a permanent `deleted` tombstone. User erasure purges personal vaults while preserving tenant-owned shared organization ciphers.
     - **Canonical Storage Metering (`POST /api/suite/storage`)**: Reports `attachment_bytes + send_file_bytes + cipher_data_bytes` per active tenant with a durable monotonic sequence.
     - **Processed-Events GC**: Periodically prunes expired replay-guard rows while preserving permanent year-9999 erasure tombstones.

## Key Environment Variables

### Rust Backend (`vaultwarden`)
| Variable | Default | Description |
| --- | --- | --- |
| `MULTI_TENANT_ENABLED` | `false` | Enables strict multi-tenant isolation & startup guardrails |
| `TENANCY_HOME_REGION` | `""` | Required region ID (e.g. `us-east-1`); matched against `tenants.home_region` |
| `TENANCY_ORG_CLAIM` | `org_id` | OIDC ID-token claim carrying KyIdentity tenant ID |
| `TENANCY_PG_NOTIFY_ENABLED` | `true` | Enables PostgreSQL `LISTEN`/`NOTIFY` multi-replica WebSocket fanout & kicks |
| `TENANCY_PG_NOTIFY_CHANNEL` | `kyvault_notify` | Safe PostgreSQL identifier (`[a-z0-9_]+`) for `LISTEN`/`NOTIFY` |
| `TENANCY_MAX_IMPORT_CIPHERS` | `5000` | Max ciphers allowed per `/import` request |
| `TENANCY_MAX_IMPORT_FOLDERS` | `500` | Max folders allowed per `/import` request |
| `TENANCY_DEFAULT_MAX_CIPHERS` | `0` | Fallback per-tenant cipher cap when `quotas_json.max_ciphers` is unset (`0` = unlimited) |

### Go Suite Worker (`kyvault-worker`)
| Variable | Required | Description |
| --- | --- | --- |
| `DATABASE_URL` | Yes | Shared PostgreSQL DSN |
| `HOME_REGION` | Yes | Region filter matching `TENANCY_HOME_REGION` |
| `KYIDENTITY_BASE_URL` | Yes | KyIdentity control plane base URL |
| `KYIDENTITY_SUITE_TOKEN` | Yes | Bearer token for `/api/suite/*` |
| `SYNC_WEBHOOK_SECRET` | Yes | Shared HMAC key (>=16 bytes) for `ky-primitives/syncauth` |
| `SSO_AUTHORITY` / `SSO_CLIENT_ID` / `OIDC_JWKS_URL` | Recommended | RS256 OIDC Back-Channel Logout verification (`ky-primitives/oidcverify`) |
| `TENANCY_PG_NOTIFY_CHANNEL` | No (`kyvault_notify`) | Shared PostgreSQL `NOTIFY` channel |
| `S3_ENDPOINT` / `S3_BUCKET` / `S3_REGION` / `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` | Optional | Enables AWS SigV4 tenant object prefix (`tenants/<id>/`) erasure |
| `DATA_FOLDER` | Optional | Enables local filesystem `tenants/<id>/` erasure |

## Running Tests

```bash
# Rust checks (PostgreSQL + S3 + SQLite)
cargo check --features postgresql,s3,sqlite
cargo test --features sqlite,s3

# Go worker unit + live PostgreSQL 16 integration tests
cd worker
go test -race ./...
KYVAULT_TEST_DATABASE_URL="postgres://kyvault:kyvault@127.0.0.1:55433/kyvault_test" go test -v -race ./...
```
