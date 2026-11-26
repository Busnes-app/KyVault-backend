# KyVault post-quantum evaluation

Date: 2026-11-25. Author: gannet (worker for the Ky PQC migration, spec B Q11).
Owner request (2026-11-25): "see if we can swap the crypto in the app with a better algorithm, if not in a worthwhile
way, change the TLS setting."

**Verdict: no worthwhile swap. KyVault switches TLS to hybrid X25519MLKEM768 now (this PR) and takes Bitwarden's
own post-quantum key sharing when it ships upstream.**

Snapshots: KyVault-backend `main` @ `c0a86c2a`; KyVault-web `main` @ `1344eb7`; `@bitwarden/sdk-internal`
`0.2.0-main.1126` (KyVault-web `package.json:189`), which is sdk-internal commit `4a9eb239` (npm `gitHead`).
SDK paths below are `bitwarden/sdk-internal @ 4a9eb239` unless marked otherwise.
Labels: **[V]** verified in code or a primary source, **[I]** inference, **[U]** unverified.

## 1. Where classical public-key crypto protects stored data

### SDK primitives [V]
- There is one public-key encryption algorithm, `PublicKeyEncryptionAlgorithm::RsaOaepSha1 = 0`
  (`crates/bitwarden-crypto/src/keys/public_key_encryption.rs:48-51`). New key pairs are RSA-2048 (`:202-213`).
- Asymmetric EncStrings (`UnsignedSharedKey`) are types 3-6, all RSA-2048. Any other type fails with
  `InvalidTypeAsymm` (`crates/bitwarden-crypto/src/enc_string/asymmetric.rs:89-117,254-259`).
- `encapsulate_key_unsigned` always writes **type 4, RSA-2048-OAEP-SHA1** (`asymmetric.rs:219-233`).
- Signatures: `SignatureAlgorithm { Ed25519, MlDsa44 }`, and the default is **ML-DSA-44**
  (`crates/bitwarden-crypto/src/signing/mod.rs:47-61`).
- KyVault-web does no RSA in TypeScript. It dispatches to the WASM SDK:
  `libs/legacy-crypto/src/services/encrypt.service.implementation.ts:206-240` (`PureCrypto.encapsulate_key_unsigned` /
  `decapsulate_key_unsigned`) and `libs/legacy-crypto/src/services/web-crypto-function.service.ts:163-193`
  (`PureCrypto.rsa_*`).

### Per feature

The backend stores every blob as opaque `TEXT` and never parses EncString types [V].

| Feature | Algorithm [V] | KyVault-web @ 1344eb7 | KyVault-backend @ c0a86c2a | Live on KyVault? |
|---|---|---|---|---|
| User key pair | RSA-2048. The private key is wrapped by the user key (AES-256-CBC-HMAC) | `libs/legacy-crypto/src/services/legacy-compat-key.service.ts:187-196` | `users.public_key`, `users.private_key` (`src/db/models/user.rs:49-51`) | Yes. The wrapped private key is symmetric, so it is PQ-safe |
| Org-key share (create, member confirm) | Type 4 to the member's public key | `legacy-compat-key.service.ts:154-167`; `apps/web/src/app/admin-console/organizations/members/components/bulk/base-bulk-confirm.component.ts:88`; `libs/admin-console/src/common/organization-user/services/default-organization-user.service.ts:50` | `users_organizations.akey` (`src/db/models/organization.rs:52`); org pair `organizations.public_key/private_key` (`:36-37`) | **Yes** |
| Admin password reset | User key encapsulated to the org public key, type 4 | `libs/common/src/auth/services/password-reset-enrollment.service.implementation.ts:63`; `apps/web/src/app/admin-console/organizations/members/services/organization-user-reset-password/organization-user-reset-password.service.ts:99,230` | `users_organizations.reset_password_key` (`organization.rs:55`) | **Yes** |
| Emergency access | Grantor user key encapsulated to the grantee, type 4 | `apps/web/src/app/auth/emergency-access/services/emergency-access.service.ts:393,571` | `emergency_access.key_encrypted` (`src/db/models/emergency_access.rs:24`) | **Yes** |
| Login with device | The requester makes an ephemeral RSA-2048 pair. The approver encapsulates the user key to it (type 4) | `libs/auth/src/angular/login-via-auth-request/login-via-auth-request.component.ts:445`; `libs/auth/src/common/services/auth-request/auth-request.service.ts:145,173` | `auth_requests.public_key`, `auth_requests.enc_key` (`src/db/models/auth_request.rs:33,35`) | **Yes**. The row is short-lived, but the ciphertext crosses the network and lands in backups |
| Trusted-device keys | Device RSA-2048 pair (`RotateableKeySet`) | `libs/common/src/key-management/device-trust/services/device-trust.service.implementation.ts:178,186` | No columns. `device.rs:126-128` hard-codes `isTrusted: false`, `encryptedUserKey: null` | No (dead code) |
| Key Connector | None. The master key goes to the connector over TLS | `libs/common/src/key-management/key-connector/services/key-connector.service.ts:250-266` | `useKeyConnector: false // Not supported` (`organization.rs:212`) | No |
| Send | Symmetric only: HKDF, then AES-256-CBC-HMAC | `legacy-compat-key.service.ts:199-203`; `libs/common/src/tools/send/services/send.service.ts:40-41,86,123` | `sends.akey`, `sends.data` (`src/db/models/send.rs:36-37`) | Yes. PQ-safe |
| V2 signing key / signed public key / security state | ML-DSA-44 signing key and a signed RSA public key (V2 accounts) | Response parsing only (`libs/common/src/key-management/keys/response/private-keys.response.ts`). Creation is behind feature flags that default to off (`libs/common/src/enums/feature-flag.enum.ts:64-69,206-211`) | Not stored. `account_keys_json()` always returns `signedPublicKey`, `securityState` and `signatureKeyPair` as null (`user.rs:269-285`) | No. Every KyVault account is V1 |

**Exposure [I]:** with a recorded database or backup and a large quantum computer, an attacker can open four
columns: `users_organizations.akey` (org keys, and so all org items), `users_organizations.reset_password_key` (user
keys of enrolled members), `emergency_access.key_encrypted` (grantor user keys) and `auth_requests.enc_key`.
Personal items, Send and the wrapped private keys are symmetric and safe.

**Correction to the stack inventory [V]:** at this SDK pin, V2 accounts use an XAES-256-GCM user key (sdk-internal
PR #1279, merged 2026-07-23), an RSA-2048 pair and an ML-DSA-44 signing key, not "XChaCha20 plus Ed25519". The
KyVault-web comment at `apps/web/src/app/key-management/key-rotation/user-key-rotation.service.ts:468-472` is stale.

## 2. Who else reads those blobs

- Every official client parses only RSA asymmetric types [V]: the web vault, browser extension, desktop app and CLI
  (bitwarden/clients, sdk-internal `0.2.0-main.1258` on main), Android (sdk-internal `56c7617b`, 2026-11-18) and iOS
  (`8da8618f`, 2026-11-16). At those commits, and on sdk-internal main @ `1474286` (2026-11-25), there is no ML-KEM,
  X-Wing, Kyber or HPKE code, enum variant or EncString type.
- **If KyVault wrote X-Wing blobs, every official client breaks [I, high confidence].** Members on mobile, desktop,
  extension or CLI could not open org keys, so org items vanish. Admins could not run account recovery and grantees
  could not take over. Login with device fails whenever one side is an official client, and the usual approver is
  the official mobile app. An X-Wing `users.public_key` also stops official clients from confirming that user into an
  org.
- A dual wrap (keep the type 4 RSA blob and add a PQ blob) keeps official clients working, but the RSA copy stays in
  the database, so it adds no protection until RSA is dropped [I].
- **KyVault does not support only KyVault-web [V].** The backend image ships upstream
  `vaultwarden/web-vault:v2026.10.1` (`docker/Dockerfile.debian:30`), not KyVault-web. The README is upstream
  Vaultwarden's and invites official clients (`README.md:3,25`). KyVault-web contains only `apps/web`, so there is no
  KyVault mobile, desktop, extension or CLI client.
- No image pipeline for the fork exists yet: `release.yml` runs only for `dani-garcia/vaultwarden` (`:40`) [V].

## 3. Bitwarden's own post-quantum plans (primary sources)

Shipped [V]:
- ML-DSA-44 signing keys for V2 accounts: sdk-internal PR #920, merged 2026-04-21
  (https://github.com/bitwarden/sdk-internal/pull/920), and server PR #7435
  (https://github.com/bitwarden/server/pull/7435).
- PQ TLS on self-hosted servers: server PR #6547, merged 2026-03-09 (https://github.com/bitwarden/server/pull/6547).
- The security whitepaper (revised 2026-11-23, https://bitwarden.com/help/bitwarden-security-white-paper/) says
  public-key encryption is RSA-OAEP and that "Bitwarden is researching post-quantum hybrid encryption schemes and will
  adopt these technologies as they mature."

Planned, not merged [V that the text exists]:
- sdk-internal issue #1252, "Post-Quantum Encryption Tracker" (open; https://github.com/bitwarden/sdk-internal/issues/1252).
  It lists org key distribution, emergency access and account recovery as not protected. A Bitwarden engineer wrote
  (2026-07-10): "We will first undergo an upgrade of organization memberships to be signcrypted 'organization
  membership v2', then as a follow-up add support for ml-kem (or x-wing / a hybrid combiner)."
- sdk-internal PR #1381, trust log spec (open since 2026-08-13; https://github.com/bitwarden/sdk-internal/pull/1381).
  It reserves a `kem` key type but names no KEM algorithm.
- An X-Wing experiment existed only in closed PR #21 (2024, "[Do not merge] crypto-next tests";
  https://github.com/bitwarden/sdk-internal/pull/21).
- "Rotateable key set" (`crates/bitwarden-crypto/src/keys/rotateable_key_set.rs:9-28`) is RSA-based, not PQ.
- No public date [V]. A KyVault-chosen format would probably not match what Bitwarden ships, because their plan is
  signcryption with an HPKE-style envelope [I].

## 4. Cost of a fork-side swap [V counts, I effort]

- Org keys are decrypted inside the WASM SDK (`libs/common/src/platform/services/sdk/default-sdk.service.ts:329-333`),
  so a TypeScript-only change is impossible. A swap means forking sdk-internal (55 files across 11 crates reference the
  RSA types), adding an algorithm variant and an EncString type number Bitwarden may later claim, building and
  hosting our own WASM package, and changing about 30 TypeScript call sites.
- Upstream moves fast: bitwarden/clients took 45 sdk-internal bumps in the three months to 2026-11-24 (about 3.5 a
  week). Each bump would need the fork rebased.
- KyVault-web has no upstream merges yet (a squashed import of vw_web_builds `v2026.10.1`; upstream `v2026.11.0` is
  out). KyVault-backend is 33 commits behind dani-garcia/vaultwarden main.
- The backend needs no schema change either way (TEXT columns).

## Verdict

Not worthwhile. A swap would break every official Bitwarden client against KyVault. It would protect only users of a
web vault that the image does not ship. It needs a permanently maintained fork of Bitwarden's SDK. And it would
probably diverge from the format Bitwarden ships later. The stored-data exposure (the four columns in section 1) stays
until Bitwarden ships PQ key sharing; KyVault should take that from upstream.

What this PR does instead (Part 2):
- rustls moves from the `ring` provider to `aws-lc-rs` with `prefer-post-quantum`. In rustls 0.23.46 that makes
  X25519MLKEM768 the first group (`rustls-0.23.46/src/crypto/aws_lc_rs/mod.rs:254-262`). Outbound TLS (reqwest
  for push, icons, HIBP, Duo and SSO; lettre SMTP; opendal S3) now offers hybrid key exchange.
- Not covered: **`ROCKET_TLS` stays classical.** Rocket 0.5.2 builds its listener from
  `rustls::crypto::ring::default_provider()` and ignores the process default
  (`rocket_http-0.5.2/src/tls/listener.rs:79-90`). Fixing that means patching Rocket. Terminate TLS at the reverse
  proxy (the Ky edge, spec B row 3) instead.
- `ring` stays in the build because Rocket requires it and `src/crypto.rs` uses it for PBKDF2 and random numbers.

## Unverified

- Docker image builds for arm64, armv7 and armv6 with aws-lc-sys (cross-compiled through `xx`). Only the host x86_64
  build and the CI container were run. See the PR's verification record.
- Whether every outbound peer (SMTP relays, S3 endpoints, the Bitwarden push relay) accepts X25519MLKEM768. rustls
  falls back to X25519 when a peer doesn't.
- Android and iOS code search for PQ terms was cut short by GitHub rate limits. Their SDK pins were checked directly.
- X-Wing key and ciphertext sizes were not needed for the verdict and were not checked.
- The PR #1 Recovery Kit wrap algorithm (spec B row 56) is still undefined in the backend.
