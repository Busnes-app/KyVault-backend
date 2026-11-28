# KyVault multi-tenancy

`Busnes-app/KyVault-backend` is an AGPL-3.0-only fork of Vaultwarden that serves many
KyIdentity organisations from one shared install. With `TENANCY_MODE=single` (the default)
it is plain Vaultwarden: no tenancy table is consulted and `/internal/tenancy/v1/*` answers
`404`.

Two processes share one PostgreSQL database:

- **`vaultwarden` (Rust, `src/`)** runs as one or more replicas. It is the **sole writer of
  every vault table**, including `tenants`, `tenant_erased_subjects`,
  `tenant_pending_deletions` and `tenant_recovery_bundles`.
- **`kyvault-worker` (Go, `worker/`)** talks to KyIdentity. It owns only
  `worker_sync_cursors`, `worker_processed_events` and `worker_known_orgs`, and changes vault
  state only by calling the Rust replicas' private API.

## Isolation in the vault

- Every user, organisation, cipher, attachment, Send and SSO link carries a `tenant_id`
  (a KyIdentity org ID, `tenants.id`). Cross-tenant reads, invites, sharing and WebSocket
  subscriptions are refused server-side. Access tokens carry the tenant in `tid`, and every
  request checks it against the user's binding.
- Sign-in is SSO only. The tenant comes from the ID token's `org_id` claim. Platform staff
  principals and erased `(issuer, subject)` pairs are refused.
- **Restricted export.** While an org is `deletion_scheduled`, KyIdentity signs the people
  it allows to export in with `"export_only": true` (KyIdentity tenancy design, "The
  `export_only` claim"). The vault admits that sign-in only for an existing vault in a served,
  app-enabled, fresh org that is `deletion_scheduled`, returns no refresh token, and the
  session reaches only `GET /api/tenancy/export`: the caller's own personal items and folders
  as stored ciphertext, with the wrapped user key and KDF settings the client unlocks them
  with. No organisation items and nothing in plaintext, so neither staff nor an organisation
  admin can export a member's vault. Every other route, the WebSocket hub and the refresh
  grant refuse export sessions, the export route refuses every other session, and an
  `export_only` sign-in never creates an account.
- **Cells (C1–C5):** The shared install scales by cells (`<geography>-<n>` slugs, e.g.
  `eu-west-1`, read from KyIdentity's `/api/suite/orgs` `home_region`, never from a token).
  One deployment serves 1–32 cells configured in `KY_CELLS` (shared tables keyed by
  `tenant_id`, never a database or schema per org).
  - **C4 (immutable placement):** Once an org's `home_region` is stored in `tenants`, it
    never changes. If an incoming snapshot disagrees with stored `home_region`, the vault
    refuses the move, fences the tenant (clears `authority_refreshed_at`, bumps
    `access_epoch`, zeroes the storage grant, rotates stamps/refresh tokens, kicks sockets),
    and reports it in `region_mismatch_tenant_ids` while the worker logs `CELL MISMATCH (C4)`.
  - **C5 (fail-closed cell boundary):** A request is served only when the tenant is `active`,
    `app_enabled`, its `home_region` is in this deployment's `KY_CELLS`, and its KyIdentity
    authority was refreshed within `TENANCY_AUTHORITY_MAX_AGE_SECS` (at most 900 s). Every
    other org is refused on every way in with `403` (or `503` when authority is stale).
- Object storage keys are cell-scoped: `cells/<cell>/tenants/<tenant_id>/attachments/<cipher>/<id>`
  and `cells/<cell>/tenants/<tenant_id>/sends/<send>/<id>`.
- Sends are always off in multi-tenant mode. Emergency access is off unless
  `TENANCY_ALLOW_EMERGENCY_ACCESS=true`.
- **Recovery Kit** (`/api/tenancy/recovery/personal`) stores only a client-wrapped user key.
  The user holds the recovery secret offline, so the server never sees plaintext. There is
  no server escrow and no organisation-admin escrow: an administrator cannot recover a
  member's vault.

### Startup refuses to run multi-tenant without

A build compiled with the private `hosted` Cargo feature, or the test-only `kye2e` feature,
which also needs an `SSO_AUTHORITY` host ending with `.test`. Public builds enable neither
and refuse `TENANCY_MODE=multi` outright. Also an `https://` `SSO_AUTHORITY`, `KY_CELLS` (1–32 unique valid cell slugs `[a-z][a-z0-9-]{0,30}[a-z0-9]`), `SSO_ENABLED=true`
and `SSO_ONLY=true`, `SIGNUPS_ALLOWED=false`, an unset `ADMIN_TOKEN`, a PostgreSQL
`DATABASE_URL`, an `s3://` `ATTACHMENTS_FOLDER`, `TENANCY_INTERNAL_API_SECRET` of at least
32 characters, `TENANCY_AUTHORITY_MAX_AGE_SECS` between 60 and 900, a
`TENANCY_PG_NOTIFY_CHANNEL` of `[a-z0-9_]{1,63}`, and a pre-provisioned `rsa_key.pem`.
Replicas must share that key. A replica never generates its own.

### Cross-replica disconnects

Fences and logouts happen inside a transaction. After it commits, the replica disconnects
its own WebSockets and publishes `user_logout` / `tenant_kick` on PostgreSQL
`NOTIFY TENANCY_PG_NOTIFY_CHANNEL`. Every other replica `LISTEN`s and disconnects the same
users. No Redis is involved. The rotated security stamps are the real revocation; the
NOTIFY only makes it immediate for open sockets.

## Private management API: `/internal/tenancy/v1/*`

Mounted at a fixed path (not under `DOMAIN`'s base path). Each call needs
`Authorization: Bearer $TENANCY_INTERNAL_API_SECRET`: a missing or wrong secret gets `401`,
and an unset or short one gets `503`. Calls naming an org outside `KY_CELLS` get `403` (C5).
**Never route this path through the public proxy.** Expose it only on the private network
the worker uses.

| Route | Does |
| --- | --- |
| `GET health` | `{status, multi_tenant, cells}` |
| `POST orgs/reconcile` | Applies KyIdentity org snapshots for served cells (`KY_CELLS`). Refuses unserved-cell orgs with `403` (C5). A stored tenant whose incoming `home_region` changed is never mutated: it is fenced and returned in `region_mismatch_tenant_ids` (C4). A newly non-active org is fenced: `access_epoch` +1, grant zeroed, every user's stamp and refresh tokens rotated, sockets kicked. `deleted` becomes `purge_pending`. Tombstoned tenants are never resurrected. |
| `POST users/logout` | Rotates stamp and refresh tokens of the exact `{issuer}/{subject}` SSO link (optionally within one tenant); refuses unserved-cell tenants with `403`. |
| `POST users/sync` | `user.created/updated/deleted`: disable/re-enable, rename. Erased subjects answer `erased_tombstone`. Refuses unserved-cell tenants with `403`. |
| `POST users/erase` | Records the permanent tombstone, queues the user's cell-scoped objects, deletes personal data. Organisation ciphers, collections and other members stay. Refuses unserved-cell tenants with `403`. |
| `POST tenants/<id>/purge/begin` | Queues every tenant object plus a `cells/<cell>/tenants/<id>/` sweep, tombstones all subjects, deletes all tenant rows. Status `purge_pending`. Refuses unserved-cell tenants with `403`. |
| `GET cleanup/pending`, `POST cleanup/complete` | The durable `tenant_pending_deletions` queue. Rows go only when the worker reports a verified deletion. Failures bump `attempts`. When a `purge_pending` tenant's queue is empty it is finalised to `deleted` with `erased_at`. |
| `POST storage/prepare`, `POST storage/apply` | The storage-grant exchange (below) |
| `POST storage/repair-seq` | Operator recovery for a `stale` sequence: sets the next report seq, which must exceed the current one. Refuses unserved-cell tenants with `403`. |

## Storage grants

Growth needs a grant from KyIdentity's pool (`POST /api/suite/storage`).

1. `storage/prepare` fixes each live tenant's report: committed bytes plus reservations,
   and the next `storage_report_seq`. Committed bytes are attachments, file Sends,
   `OCTET_LENGTH(ciphers.data)` and active Recovery Kit envelopes. The report is stored as
   pending, so a failed exchange is resent with the **same seq and bytes**, which KyIdentity
   treats as a replay. Non-active tenants report `want_bytes: 0`.
2. The worker sends the batch, noting `sent_at` before the request leaves.
3. `storage/apply` installs `ok` grants. Expiry is `min(sent_at, now) + ttl`, with ttl capped
   at 900 s. Out-of-order seqs are ignored. An answer for a tenant fenced in the meantime
   records the seq but installs no grant.
4. Uploads take the grant under `SELECT … FOR UPDATE` on the tenant row:
   `committed + reserved + new <= ceiling`, an unexpired grant, and not over the pool. The
   attachment row is saved and its reservation released in one transaction, so concurrent
   uploads on any replica never over- or double-count. An upload finishes only if the
   tenant's `access_epoch` is unchanged.

`stale` (KyIdentity holds a newer seq, as after a database restore) sets
`storage_seq_stale`. The tenant keeps its existing grant until expiry, stops reporting, and
its seq is **never reset automatically**. The worker logs `STORAGE SEQUENCE STALE`. An
operator calls `storage/repair-seq` with a `next_seq` above KyIdentity's.

## The worker

Built on `github.com/Busnes-app/ky-primitives`: `suitedir` (KyIdentity
`/api/suite/{orgs,erased,storage}` with `client_secret_basic`), `syncauth` (signed webhooks)
and `oidcverify` (RS256 back-channel logout).

- **Startup** verifies the vault's `/internal/tenancy/v1/health` `cells` matches the worker's
  `KY_CELLS`, then reconciles orgs and erased subjects before `/readyz` turns ready and
  webhooks are accepted.
- **Orgs** are polled from the saved cursor. Orgs outside `KY_CELLS` are skipped (C5),
  except previously-served orgs whose `home_region` changed (forwarded so the vault executes
  C4 fencing and logs `CELL MISMATCH (C4)`). Each served org's initial cell is recorded
  immutably in `worker_known_orgs`. `purge_required` tenants go to `purge/begin`. The cursor
  is saved only after the vault accepted the page.
- **Erased subjects** are polled, filtered by `worker_known_orgs` (refreshing orgs once if
  an org is unseen) so foreign-cell erasures do not stall the cursor, and sent to
  `users/erase` using the same cursor rule.
- **Storage**: every interval it runs prepare → KyIdentity → apply, never with two reports
  in flight for one org.
- **Cleanup** drains `cleanup/pending` against the same storage roots the vault uses, then
  reports to `cleanup/complete`. Local roots go through `os.Root`. S3 roots delete every
  object version and abort multipart uploads. A missing root or S3 error leaves the item
  pending. Keys outside `cells/<served_cell>/tenants/<id>/` are refused.
- **`POST /api/sync/events`** verifies `X-KySignOn-*` (`syncauth`), then forwards
  `user.created/updated/deleted/erased`. **`POST /api/oidc/backchannel-logout`** verifies the
  `logout+jwt` against the issuer's JWKS and calls `users/logout`. Both claim the event in
  `worker_processed_events`, and mark it completed **only after the vault applied it**. An
  unserved-cell refusal propagates `403` (C5); a transient failure answers `502` and stays
  retryable; a completed one answers `200 {"status":"duplicate"}`.
- **Restore**: after restoring the vault database from backup, start one worker with
  `TENANCY_RECONCILE_FROM_ZERO=true`. It replays orgs and erasures from revision 0 before it
  becomes ready. Storage seqs are untouched: a `stale` answer then goes through
  `repair-seq`.

## Configuration

### Rust replicas (multi-tenant)

| Variable | Default | |
| --- | --- | --- |
| `TENANCY_MODE` | `single` | `multi` enables everything above |
| `KY_CELLS` | — | Comma-separated list of 1–32 cell slugs this deployment serves (e.g. `eu-west-1,eu-west-2`); orgs homed elsewhere are refused with `403` (C5) |
| `TENANCY_INTERNAL_API_SECRET` | — | ≥ 32 chars, shared with the worker |
| `TENANCY_AUTHORITY_MAX_AGE_SECS` | `900` | 60–900 |
| `TENANCY_PG_NOTIFY_ENABLED` | `true` | Cross-replica disconnects |
| `TENANCY_PG_NOTIFY_CHANNEL` | `kyvault_notify` | `[a-z0-9_]{1,63}` |
| `TENANCY_MAX_IMPORT_CIPHERS` / `TENANCY_MAX_IMPORT_FOLDERS` | `5000` / `500` | Per import request |
| `TENANCY_ALLOW_EMERGENCY_ACCESS` | `false` | |
| `TENANCY_MAX_CIPHERS_PER_TENANT` | `50000` | Default when the org's quotas set no `max_ciphers` |
| `ATTACHMENTS_FOLDER` | — | `s3://bucket/prefix?endpoint=…&region=…`; credentials from the AWS chain |

Plus the Vaultwarden SSO settings (`SSO_ENABLED`, `SSO_ONLY`, `SSO_AUTHORITY`,
`SSO_CLIENT_ID`, `SSO_CLIENT_SECRET`), `DATABASE_URL` and `DOMAIN`, which all replicas share.

### Worker (`kyvault-worker`)

| Variable | Default | |
| --- | --- | --- |
| `DATABASE_URL` | required | The vault's PostgreSQL (worker tables only) |
| `KY_CELLS` | required | Comma-separated list of 1–32 cell slugs; must match the vault replicas' `KY_CELLS` |
| `VAULT_INTERNAL_API_URL` | required | A replica's private base URL. `https` anywhere, plain `http` only to loopback, private or single-label hosts. |
| `TENANCY_INTERNAL_API_SECRET` | required | Same as the replicas |
| `SSO_AUTHORITY` | required | OIDC issuer; also the KyIdentity base URL |
| `KYIDENTITY_BASE_URL` | `SSO_AUTHORITY` | Override for `/api/suite/*` |
| `SSO_CLIENT_ID` / `SSO_CLIENT_SECRET` | required | Suite directory credentials and logout audience |
| `OIDC_JWKS_URL` | `$SSO_AUTHORITY/.well-known/jwks.json` | |
| `SYNC_WEBHOOK_SECRET` | required | ≥ 32 chars |
| `WORKER_LISTEN_ADDR` | `127.0.0.1:8085` | |
| `ORG_POLL_INTERVAL` / `ERASED_POLL_INTERVAL` / `STORAGE_REPORT_INTERVAL` | `30s` | Clamped to ≤ 60 s |
| `CLEANUP_INTERVAL` | `60s` | Clamped to ≤ 60 s |
| `PRUNE_INTERVAL` | `1h` | Expired `worker_processed_events` |
| `STORAGE_WANT_BYTES` | `268435456` | Growth requested per active tenant |
| `STORAGE_RENEW_BEFORE` | `180s` | < 900 s. Sent to the vault, which currently reports every live tenant on each pass. |
| `TENANCY_RECONCILE_FROM_ZERO` | `false` | Restore reconciliation (above) |
| `ATTACHMENTS_FOLDER` / `SENDS_FOLDER` | `$DATA_FOLDER/attachments` / `…/sends` | The vault's roots: a local dir or `s3://bucket/prefix` with no query string |
| `S3_ENDPOINT` / `S3_REGION` / `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` / `S3_FORCE_PATH_STYLE` | — / `us-east-1` / — / — / `true` | For `s3://` roots |

## Tests

```bash
cargo test --features sqlite,s3            # tenancy ops run against SQLite
cd worker && GOWORK=off go test -race ./...

# Live: Rust built with PostgreSQL and `kye2e` in Docker, two multi-tenant replicas and one
# single-tenant SQLite replica, PostgreSQL 18, RustFS, the worker binary and a TLS
# KyIdentity fake on the SUITE-DIRECTORY.md wire format that is also the OIDC provider.
# TestLiveHostedJourney signs in through SSO, unlocks with the master password, recovers
# with a Personal Recovery Kit, restores the database from pg_dump, checks isolation and
# runs the restricted export.
worker/e2e/run.sh            # --clean also drops the cargo cache volumes
worker/e2e/cargo.sh test --features postgresql,s3
```
