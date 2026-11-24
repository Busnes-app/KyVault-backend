# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS builder
WORKDIR /src

# Private Busnes-app Go module (ky-primitives) requires GOPRIVATE and git credentials at build time.
ARG GOPRIVATE=github.com/Busnes-app/*
ENV GOPRIVATE=${GOPRIVATE}
RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN --mount=type=secret,id=git_credentials,target=/root/.git-credentials \
    git config --global credential.helper store && \
    go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/kyvault-worker ./cmd/kyvault-worker

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/kyvault-worker /usr/local/bin/kyvault-worker
USER nonroot:nonroot
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/kyvault-worker"]
