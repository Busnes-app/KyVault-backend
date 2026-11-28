// Package config loads the worker's environment. Every value is validated here; an
// unparsable or missing setting refuses startup instead of falling back silently.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

// MaxPollInterval is the suite's observation bound (design §7): KyIdentity state is
// polled at most this far apart.
const MaxPollInterval = 60 * time.Second

// MinInternalSecretLen is the minimum TENANCY_INTERNAL_API_SECRET length.
const MinInternalSecretLen = 32

// MaxCells is the maximum number of cells one deployment may serve (Cells C2).
const MaxCells = 32

type Config struct {
	ListenAddr  string
	DatabaseURL string

	// Cells is the set of home_region slugs this deployment serves (KY_CELLS, C1/C2/C5).
	Cells []string

	// Rust vault private management API.
	VaultAPIURL    string
	InternalSecret string

	// KyIdentity: suite directory (client_secret_basic), OIDC logout, signed webhooks.
	KyIdentityURL     string
	OIDCIssuer        string
	ClientID          string
	ClientSecret      string
	OIDCJWKSURL       string
	SyncWebhookSecret string

	OrgPollInterval    time.Duration
	ErasedPollInterval time.Duration
	StorageInterval    time.Duration
	CleanupInterval    time.Duration
	PruneInterval      time.Duration
	ReconcileFromZero  bool

	StorageWantBytes   int64
	StorageRenewBefore time.Duration

	// Storage roots, exactly as the Rust server resolves them: a local directory or
	// s3://bucket/prefix[?endpoint=…&region=…&enable_virtual_host_style=…]. Object keys
	// (cells/<cell>/tenants/<tid>/...) are relative to these.
	AttachmentsRoot string
	SendsRoot       string

	S3Endpoint        string
	S3Region          string
	S3AccessKeyID     string
	S3SecretAccessKey string
	S3ForcePathStyle  bool
	// S3EnvOptions names the legacy S3_ENDPOINT/S3_REGION/S3_FORCE_PATH_STYLE settings that
	// are set; they cannot be mixed with options in an s3:// root.
	S3EnvOptions []string

	// Warnings lists settings LoadFromEnv adjusted, for the caller to log.
	Warnings []string
}

// LoadFromEnv reads and validates the configuration.
func LoadFromEnv() (Config, error) {
	var errs []error
	durationVar := func(key string, def time.Duration) time.Duration {
		d, err := envDuration(key, def)
		errs = append(errs, err)
		return d
	}
	boolVar := func(key string, def bool) bool {
		b, err := envBool(key, def)
		errs = append(errs, err)
		return b
	}

	cells, err := ParseCells(env("KY_CELLS"))
	if err != nil {
		errs = append(errs, fmt.Errorf("KY_CELLS: %w", err))
	}

	var s3EnvOptions []string
	for _, k := range []string{"S3_ENDPOINT", "S3_REGION", "S3_FORCE_PATH_STYLE"} {
		if env(k) != "" {
			s3EnvOptions = append(s3EnvOptions, k)
		}
	}

	issuer := strings.TrimRight(env("SSO_AUTHORITY"), "/")
	dataFolder := env("DATA_FOLDER")
	cfg := Config{
		ListenAddr:         envOr("WORKER_LISTEN_ADDR", "127.0.0.1:8085"),
		DatabaseURL:        env("DATABASE_URL"),
		Cells:              cells,
		VaultAPIURL:        strings.TrimRight(env("VAULT_INTERNAL_API_URL"), "/"),
		InternalSecret:     env("TENANCY_INTERNAL_API_SECRET"),
		KyIdentityURL:      strings.TrimRight(envOr("KYIDENTITY_BASE_URL", issuer), "/"),
		OIDCIssuer:         issuer,
		ClientID:           env("SSO_CLIENT_ID"),
		ClientSecret:       env("SSO_CLIENT_SECRET"),
		OIDCJWKSURL:        env("OIDC_JWKS_URL"),
		SyncWebhookSecret:  env("SYNC_WEBHOOK_SECRET"),
		OrgPollInterval:    durationVar("ORG_POLL_INTERVAL", 30*time.Second),
		ErasedPollInterval: durationVar("ERASED_POLL_INTERVAL", 30*time.Second),
		StorageInterval:    durationVar("STORAGE_REPORT_INTERVAL", 30*time.Second),
		CleanupInterval:    durationVar("CLEANUP_INTERVAL", 60*time.Second),
		PruneInterval:      durationVar("PRUNE_INTERVAL", time.Hour),
		ReconcileFromZero:  boolVar("TENANCY_RECONCILE_FROM_ZERO", false),
		StorageRenewBefore: durationVar("STORAGE_RENEW_BEFORE", 180*time.Second),
		AttachmentsRoot:    envOr("ATTACHMENTS_FOLDER", joinRoot(dataFolder, "attachments")),
		SendsRoot:          envOr("SENDS_FOLDER", joinRoot(dataFolder, "sends")),
		S3Endpoint:         strings.TrimRight(env("S3_ENDPOINT"), "/"),
		S3Region:           envOr("S3_REGION", envOr("AWS_REGION", "us-east-1")),
		S3AccessKeyID:      envOr("S3_ACCESS_KEY_ID", env("AWS_ACCESS_KEY_ID")),
		S3SecretAccessKey:  envOr("S3_SECRET_ACCESS_KEY", env("AWS_SECRET_ACCESS_KEY")),
		// Legacy S3_* configs default to path style; otherwise virtual host, as the backend.
		S3ForcePathStyle: boolVar("S3_FORCE_PATH_STYLE", len(s3EnvOptions) > 0),
		S3EnvOptions:     s3EnvOptions,
	}
	want, err := envInt("STORAGE_WANT_BYTES", 256<<20)
	errs = append(errs, err)
	cfg.StorageWantBytes = want

	if err := errors.Join(errs...); err != nil {
		return Config{}, err
	}
	for _, d := range []struct {
		name string
		v    *time.Duration
	}{
		{"ORG_POLL_INTERVAL", &cfg.OrgPollInterval},
		{"ERASED_POLL_INTERVAL", &cfg.ErasedPollInterval},
		{"STORAGE_REPORT_INTERVAL", &cfg.StorageInterval},
		{"CLEANUP_INTERVAL", &cfg.CleanupInterval},
	} {
		if *d.v > MaxPollInterval {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("%s %s clamped to %s", d.name, *d.v, MaxPollInterval))
			*d.v = MaxPollInterval
		}
	}
	if cfg.OIDCJWKSURL == "" && cfg.OIDCIssuer != "" {
		cfg.OIDCJWKSURL = cfg.OIDCIssuer + "/.well-known/jwks.json"
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks required settings.
func (c Config) Validate() error {
	var errs []error
	req := func(name, v string) {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	req("DATABASE_URL", c.DatabaseURL)
	req("VAULT_INTERNAL_API_URL", c.VaultAPIURL)
	req("SSO_AUTHORITY", c.OIDCIssuer)
	req("SSO_CLIENT_ID", c.ClientID)
	req("SSO_CLIENT_SECRET", c.ClientSecret)
	req("SYNC_WEBHOOK_SECRET", c.SyncWebhookSecret)

	if err := ValidateCells(c.Cells); err != nil {
		errs = append(errs, fmt.Errorf("KY_CELLS: %w", err))
	}
	if c.DatabaseURL != "" && !strings.HasPrefix(c.DatabaseURL, "postgres://") && !strings.HasPrefix(c.DatabaseURL, "postgresql://") {
		errs = append(errs, errors.New("DATABASE_URL must be a PostgreSQL connection string"))
	}
	if len(c.InternalSecret) < MinInternalSecretLen {
		errs = append(errs, fmt.Errorf("TENANCY_INTERNAL_API_SECRET must be at least %d characters", MinInternalSecretLen))
	}
	if c.VaultAPIURL != "" {
		if err := ValidateInternalURL(c.VaultAPIURL); err != nil {
			errs = append(errs, fmt.Errorf("VAULT_INTERNAL_API_URL: %w", err))
		}
	}
	if len(c.SyncWebhookSecret) > 0 && len(c.SyncWebhookSecret) < 32 {
		errs = append(errs, errors.New("SYNC_WEBHOOK_SECRET must be at least 32 characters"))
	}
	if c.StorageWantBytes < 0 || c.StorageWantBytes > 1<<53 {
		errs = append(errs, errors.New("STORAGE_WANT_BYTES must be 0 to 2^53"))
	}
	if c.StorageRenewBefore >= 900*time.Second {
		errs = append(errs, errors.New("STORAGE_RENEW_BEFORE must be under 900s, the longest grant"))
	}
	usesS3 := strings.HasPrefix(c.AttachmentsRoot, "s3://") || strings.HasPrefix(c.SendsRoot, "s3://")
	if usesS3 && (c.S3AccessKeyID == "" || c.S3SecretAccessKey == "") {
		errs = append(errs, errors.New("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (or S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY) are required for s3:// storage roots"))
	}
	for _, r := range []struct{ name, root string }{{"ATTACHMENTS_FOLDER", c.AttachmentsRoot}, {"SENDS_FOLDER", c.SendsRoot}} {
		if strings.HasPrefix(r.root, "s3://") && strings.Contains(r.root, "?") && len(c.S3EnvOptions) > 0 {
			errs = append(errs, fmt.Errorf("%s carries S3 options; unset %s", r.name, strings.Join(c.S3EnvOptions, ", ")))
		}
	}
	return errors.Join(errs...)
}

// IsValidCellSlug reports whether s matches ^[a-z][a-z0-9-]{1,31}$, the cell / home_region
// slug grammar shared with the Rust server and KyIdentity.
func IsValidCellSlug(s string) bool {
	if len(s) < 2 || len(s) > 32 {
		return false
	}
	if s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

// ParseCells parses a comma-separated KY_CELLS list into 1..=MaxCells unique valid slugs.
func ParseCells(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("must list at least one cell slug")
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	if err := ValidateCells(out); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateCells enforces 1..=MaxCells unique valid cell slugs.
func ValidateCells(cells []string) error {
	if len(cells) == 0 {
		return errors.New("must list at least one cell slug")
	}
	if len(cells) > MaxCells {
		return fmt.Errorf("may list at most %d cells (got %d)", MaxCells, len(cells))
	}
	seen := make(map[string]struct{}, len(cells))
	for _, c := range cells {
		if !IsValidCellSlug(c) {
			return fmt.Errorf("invalid cell slug %q", c)
		}
		if _, dup := seen[c]; dup {
			return fmt.Errorf("duplicate cell slug %q", c)
		}
		seen[c] = struct{}{}
	}
	return nil
}

// ValidateInternalURL accepts https anywhere, and plain http only to a loopback, private
// or single-label (container network) host: the bearer secret never crosses the internet
// in clear.
func ValidateInternalURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be an absolute URL without credentials, query or fragment")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
			return nil
		}
		if host == "localhost" || !strings.Contains(host, ".") {
			return nil
		}
		return errors.New("plain http is allowed only to a loopback, private or single-label host")
	default:
		return errors.New("scheme must be http or https")
	}
}

func joinRoot(base, child string) string {
	if base == "" {
		return ""
	}
	if strings.HasPrefix(base, "s3://") {
		// Before the options, as the backend's join_path does.
		p, q, hasQ := strings.Cut(base, "?")
		if hasQ {
			q = "?" + q
		}
		return strings.TrimRight(p, "/") + "/" + child + q
	}
	return path.Join(base, child)
}

func env(key string) string { return strings.TrimSpace(os.Getenv(key)) }

func envOr(key, fallback string) string {
	if v := env(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) (bool, error) {
	v := env(key)
	if v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback, fmt.Errorf("%s: not a boolean: %q", key, v)
	}
	return b, nil
}

func envInt(key string, fallback int64) (int64, error) {
	v := env(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback, fmt.Errorf("%s: not an integer: %q", key, v)
	}
	return n, nil
}

// envDuration accepts a Go duration ("30s") or whole seconds ("30").
func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	v := env(key)
	if v == "" {
		return fallback, nil
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d, nil
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second, nil
	}
	return fallback, fmt.Errorf("%s: not a positive duration: %q", key, v)
}
