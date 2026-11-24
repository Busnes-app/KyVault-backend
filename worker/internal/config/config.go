package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds runtime configuration for the kyvault-worker sidecar.
type Config struct {
	ListenAddr   string
	DatabaseURL  string
	HomeRegion   string
	NotifyChan   string
	WorkerOrigin string

	// KyIdentity control plane & OIDC verification.
	KyIdentityBaseURL   string
	KyIdentityToken     string
	OIDCIssuer          string
	OIDCAudience        string
	OIDCJWKSURL         string
	SyncWebhookSecret   string
	SyncAllowInsecureHTTP bool

	// Polling intervals.
	OrgPollInterval       time.Duration
	ErasedPollInterval    time.Duration
	StorageReportInterval time.Duration
	PruneInterval         time.Duration

	// Object storage erasure configuration (S3-compatible and/or local filesystem).
	S3Endpoint        string
	S3Bucket          string
	S3Region          string
	S3AccessKeyID     string
	S3SecretAccessKey string
	S3ForcePathStyle  bool
	S3Prefix          string
	LocalDataFolder   string
}

// LoadFromEnv loads worker configuration from environment variables and validates
// fail-closed multi-tenant invariants.
func LoadFromEnv() (Config, error) {
	cfg := Config{
		ListenAddr:            envOr("WORKER_LISTEN_ADDR", "127.0.0.1:8085"),
		DatabaseURL:           strings.TrimSpace(os.Getenv("DATABASE_URL")),
		HomeRegion:            strings.TrimSpace(envOr("HOME_REGION", "us")),
		NotifyChan:            strings.TrimSpace(envOr("TENANCY_PG_NOTIFY_CHANNEL", "kyvault_notify")),
		WorkerOrigin:          strings.TrimSpace(envOr("WORKER_ORIGIN", "kyvault-worker")),
		KyIdentityBaseURL:     strings.TrimRight(strings.TrimSpace(os.Getenv("KYIDENTITY_BASE_URL")), "/"),
		KyIdentityToken:       strings.TrimSpace(os.Getenv("KYIDENTITY_SUITE_TOKEN")),
		OIDCIssuer:            strings.TrimRight(strings.TrimSpace(os.Getenv("SSO_AUTHORITY")), "/"),
		OIDCAudience:          strings.TrimSpace(os.Getenv("SSO_CLIENT_ID")),
		OIDCJWKSURL:           strings.TrimSpace(os.Getenv("OIDC_JWKS_URL")),
		SyncWebhookSecret:     strings.TrimSpace(os.Getenv("SYNC_WEBHOOK_SECRET")),
		SyncAllowInsecureHTTP: envBool("SYNC_ALLOW_INSECURE_HTTP", false),
		OrgPollInterval:       envDuration("ORG_POLL_INTERVAL", 60*time.Second),
		ErasedPollInterval:    envDuration("ERASED_POLL_INTERVAL", 60*time.Second),
		StorageReportInterval: envDuration("STORAGE_REPORT_INTERVAL", 60*time.Second),
		PruneInterval:         envDuration("PRUNE_INTERVAL", time.Hour),
		S3Endpoint:            strings.TrimRight(strings.TrimSpace(os.Getenv("S3_ENDPOINT")), "/"),
		S3Bucket:              strings.TrimSpace(os.Getenv("S3_BUCKET")),
		S3Region:              strings.TrimSpace(envOr("S3_REGION", "us-east-1")),
		S3AccessKeyID:         strings.TrimSpace(os.Getenv("S3_ACCESS_KEY_ID")),
		S3SecretAccessKey:     strings.TrimSpace(os.Getenv("S3_SECRET_ACCESS_KEY")),
		S3ForcePathStyle:      envBool("S3_FORCE_PATH_STYLE", true),
		S3Prefix:              strings.Trim(strings.TrimSpace(os.Getenv("S3_KEY_PREFIX")), "/"),
		LocalDataFolder:       strings.TrimSpace(os.Getenv("DATA_FOLDER")),
	}

	if cfg.OIDCIssuer == "" && cfg.KyIdentityBaseURL != "" {
		cfg.OIDCIssuer = cfg.KyIdentityBaseURL
	}
	if cfg.OIDCJWKSURL == "" && cfg.OIDCIssuer != "" {
		cfg.OIDCJWKSURL = cfg.OIDCIssuer + "/.well-known/jwks.json"
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks required settings and safe identifier constraints.
func (c Config) Validate() error {
	if c.DatabaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	if !strings.HasPrefix(c.DatabaseURL, "postgres://") && !strings.HasPrefix(c.DatabaseURL, "postgresql://") {
		return errors.New("DATABASE_URL must be a PostgreSQL connection string")
	}
	if c.HomeRegion == "" {
		return errors.New("HOME_REGION is required")
	}
	if !isSafeIdentifier(c.NotifyChan) {
		return fmt.Errorf("TENANCY_PG_NOTIFY_CHANNEL %q must contain only [a-zA-Z0-9_]", c.NotifyChan)
	}
	if c.S3Bucket != "" && (c.S3AccessKeyID == "" || c.S3SecretAccessKey == "") {
		return errors.New("S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY are required when S3_BUCKET is set")
	}
	return nil
}

func isSafeIdentifier(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return fallback
}
