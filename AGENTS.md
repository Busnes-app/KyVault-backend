# Purpose

KyVault-backend is the Busnes-app Vaultwarden fork, with a Go directory-sync worker.

# Ownership

- `src/`, `macros/`, `migrations/` and `Cargo.*` own the Rust server.
- `worker/` owns the Go worker and its live integration harness.
- `.github/workflows/` and `scripts/` own CI and repository checks.

# Local Contracts

- Rust outbound TLS uses `rustls_crypto_provider()` in `src/main.rs` (aws-lc-rs
  with `prefer-post-quantum`). Its loopback test must negotiate TLS 1.3 and
  X25519MLKEM768 using that provider's default groups on both peers.
- Rocket's `ROCKET_TLS` listener still uses ring; the outbound handshake test
  makes no claim about inbound TLS or peers that only support classical exchange.
- Keep the worker's Go key exchange defaults. The override guard rejects
  `CurvePreferences` and `tlsmlkem` in worker Go files, including tests.
- Worker PQ tests use `ky-primitives/pqtls.RequireHybrid` and run in separate
  default and `GODEBUG=fips140=on` processes.

# Work Guidance

# Verification

- Rust CI's database/feature matrix, Clippy and formatting checks live in
  `.github/workflows/build.yml`. The focused handshake check is
  `cargo test --locked --features sqlite tls_tests::tls13_handshake_negotiates_x25519mlkem768`.
- `worker/e2e/cargo.sh` provides database client libraries and persistent Docker
  caches when the host lacks them. Create the ignored `data/` directory before
  full unit tests: the read-only checkout mount cannot create it for config validation.
  Live integration runs use `worker/e2e/run.sh`.
- Run `scripts/check-pqc-tls.sh`; from `worker/`, run `go test -race ./...` and
  `GODEBUG=fips140=on go test -count=1 -v -run PQ ./...`. CI uses `worker/go.mod`'s Go version.

# Child DOX Index
