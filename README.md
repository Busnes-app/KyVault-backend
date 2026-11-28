# KyVault-backend

**Busnes-app's AGPL-3.0 fork of [Vaultwarden](https://github.com/dani-garcia/vaultwarden)** — a Rust server implementation of the Bitwarden Client API compatible with [official Bitwarden clients](https://bitwarden.com/download/) and paired with [KyVault-web](https://github.com/Busnes-app/KyVault-web) in the [Busnes.app](https://busnes.app) Ky suite.

> [!IMPORTANT]
> **Report bugs and issues for this fork in [Busnes-app/KyVault-backend](https://github.com/Busnes-app/KyVault-backend/issues).** Do not use upstream Vaultwarden or official Bitwarden support channels for issues with this fork. For private vulnerability reports, see [SECURITY.md](SECURITY.md) or use the repository's GitHub **Security** tab.

## Features

Implements the Bitwarden Client API, including:

- [Personal Vault](https://bitwarden.com/help/managing-items/)
- [Send](https://bitwarden.com/help/about-send/)
- [Attachments](https://bitwarden.com/help/attachments/)
- [Website icons](https://bitwarden.com/help/website-icons/)
- [Personal API Key](https://bitwarden.com/help/personal-api-key/)
- [Organizations](https://bitwarden.com/help/getting-started-organizations/) — collections, password sharing, member roles, groups, event logs, admin password reset, directory connector, and policies
- [Multi/Two Factor Authentication](https://bitwarden.com/help/bitwarden-field-guide-two-step-login/) — authenticator TOTP, email, FIDO2 WebAuthn, YubiKey, and Duo
- [Emergency Access](https://bitwarden.com/help/emergency-access/)
- [Admin backend](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-admin-page)
- Web vault support — pairs with [KyVault-web](https://github.com/Busnes-app/KyVault-web) (or upstream [bw_web_builds](https://github.com/dani-garcia/bw_web_builds))

## Usage and operations

> [!IMPORTANT]
> The web vault requires HTTPS and a secure context for the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). Run behind a TLS-terminating reverse proxy in production (see upstream [HTTPS guidance](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-HTTPS) and [proxy examples](https://github.com/dani-garcia/vaultwarden/wiki/Proxy-examples)).

### Building container images

See [docker/README.md](docker/README.md) for `docker buildx bake`, `docker/bake.sh`, and `docker/podman-bake.sh` instructions for Debian and Alpine multi-architecture images.

To run a locally built container with persistent storage:

```shell
docker run --detach --name kyvault-backend \
  --env DOMAIN="https://vault.example.com" \
  --volume ./vw-data/:/data/ \
  --restart unless-stopped \
  --publish 127.0.0.1:8000:80 \
  vaultwarden/server:testing
```

Or with Docker Compose:

```yaml
services:
  kyvault-backend:
    image: vaultwarden/server:testing
    container_name: kyvault-backend
    restart: unless-stopped
    environment:
      DOMAIN: "https://vault.example.com"
    volumes:
      - ./vw-data/:/data/
    ports:
      - 127.0.0.1:8000:80
```

### Private hosted image (multi-tenant)

`TENANCY_MODE=multi` runs only in a binary built with the private `hosted` Cargo feature (see [MULTI_TENANCY.md](MULTI_TENANCY.md)). Public images and release workflows never enable it, and CI fails if they do (`scripts/check-public-image-features.sh`). Build the hosted image by hand and push it only to the private registry:

```shell
docker build --build-arg DB=postgresql,s3,hosted -t <private-registry>/kyvault-backend:hosted .
```

> [!CAUTION]
> Never push a `hosted` image to a public registry (Docker Hub, public GHCR, Quay) or tag it with a public image name. The test-only `kye2e` feature is never used for hosted builds.

Configuration variables are documented in [`.env.template`](.env.template) and the upstream [Vaultwarden Wiki](https://github.com/dani-garcia/vaultwarden/wiki).

### Building from source and testing

This workspace targets the Rust toolchain pinned in [`rust-toolchain.toml`](rust-toolchain.toml) and supports `sqlite`, `mysql`, and `postgresql` Diesel backends (configured via Cargo features in [`Cargo.toml`](Cargo.toml)).

For Playwright end-to-end and OIDC integration tests across database backends, see [playwright/README.md](playwright/README.md).

## Upstream attribution and license

`KyVault-backend` is forked from [dani-garcia/vaultwarden](https://github.com/dani-garcia/vaultwarden) (formerly `bitwarden_rs`) and is licensed under the GNU Affero General Public License v3.0 — see [LICENSE.txt](LICENSE.txt).

## Disclaimer

**This project is not associated with [Bitwarden](https://bitwarden.com/), Bitwarden, Inc., or upstream Vaultwarden maintainers.**

We cannot be held liable for any data loss that may occur while running this server, including passwords, attachments, and database state. Maintain regular, tested backups of your data directory and database.
