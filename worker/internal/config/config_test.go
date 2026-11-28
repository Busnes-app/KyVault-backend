package config

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func setBase(t *testing.T) {
	for k, v := range map[string]string{
		"DATABASE_URL":                "postgres://w@db/worker",
		"KY_CELLS":                    "eu-west-1,eu-west-2",
		"VAULT_INTERNAL_API_URL":      "http://vault:8000",
		"TENANCY_INTERNAL_API_SECRET": strings.Repeat("s", 32),
		"SSO_AUTHORITY":               "https://id.example/",
		"SSO_CLIENT_ID":               "kyvault",
		"SSO_CLIENT_SECRET":           "secret",
		"SYNC_WEBHOOK_SECRET":         strings.Repeat("w", 32),
		"DATA_FOLDER":                 "/data",
	} {
		t.Setenv(k, v)
	}
}

func TestDefaults(t *testing.T) {
	setBase(t)
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.Cells, []string{"eu-west-1", "eu-west-2"}) {
		t.Fatalf("cells: %v", cfg.Cells)
	}
	if cfg.OIDCIssuer != "https://id.example" || cfg.KyIdentityURL != cfg.OIDCIssuer || cfg.OIDCJWKSURL != "https://id.example/.well-known/jwks.json" {
		t.Fatalf("issuer defaults: %+v", cfg)
	}
	if cfg.AttachmentsRoot != "/data/attachments" || cfg.SendsRoot != "/data/sends" {
		t.Fatalf("roots: %q %q", cfg.AttachmentsRoot, cfg.SendsRoot)
	}
	if cfg.OrgPollInterval != 30*time.Second || cfg.ReconcileFromZero {
		t.Fatalf("intervals: %+v", cfg)
	}
}

func TestS3RootsAndClamp(t *testing.T) {
	setBase(t)
	t.Setenv("DATA_FOLDER", "s3://bucket/data/")
	t.Setenv("S3_ACCESS_KEY_ID", "k")
	t.Setenv("S3_SECRET_ACCESS_KEY", "s")
	t.Setenv("ORG_POLL_INTERVAL", "5m")
	t.Setenv("TENANCY_RECONCILE_FROM_ZERO", "true")
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AttachmentsRoot != "s3://bucket/data/attachments" || cfg.SendsRoot != "s3://bucket/data/sends" {
		t.Fatalf("roots: %q %q", cfg.AttachmentsRoot, cfg.SendsRoot)
	}
	if cfg.OrgPollInterval != MaxPollInterval || len(cfg.Warnings) != 1 || !cfg.ReconcileFromZero {
		t.Fatalf("clamp: %v %v", cfg.OrgPollInterval, cfg.Warnings)
	}
}

func TestBackendS3Root(t *testing.T) {
	raw, err := os.ReadFile("../s3clean/testdata/backend-s3-root.txt")
	if err != nil {
		t.Fatal(err)
	}
	root := strings.TrimSpace(string(raw))
	setBase(t)
	t.Setenv("ATTACHMENTS_FOLDER", root)
	t.Setenv("AWS_ACCESS_KEY_ID", "k")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "s")
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AttachmentsRoot != root || cfg.S3AccessKeyID != "k" || cfg.S3SecretAccessKey != "s" || cfg.S3ForcePathStyle {
		t.Fatalf("backend root: %+v", cfg)
	}

	t.Setenv("ATTACHMENTS_FOLDER", "")
	t.Setenv("DATA_FOLDER", "s3://b/data/?region=fsn1")
	if cfg, err = LoadFromEnv(); err != nil || cfg.SendsRoot != "s3://b/data/sends?region=fsn1" {
		t.Fatalf("joined %q: %v", cfg.SendsRoot, err)
	}

	for _, k := range []string{"S3_ENDPOINT", "S3_REGION", "S3_FORCE_PATH_STYLE"} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, "true")
			if _, err := LoadFromEnv(); err == nil || !strings.Contains(err.Error(), k) {
				t.Fatalf("%s mixed with root options: %v", k, err)
			}
		})
	}
}

func TestLegacyS3Env(t *testing.T) {
	setBase(t)
	t.Setenv("ATTACHMENTS_FOLDER", "s3://b/a")
	t.Setenv("S3_ENDPOINT", "http://minio:9000/")
	t.Setenv("S3_ACCESS_KEY_ID", "k")
	t.Setenv("S3_SECRET_ACCESS_KEY", "s")
	t.Setenv("AWS_ACCESS_KEY_ID", "other")
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.S3Endpoint != "http://minio:9000" || cfg.S3Region != "us-east-1" || !cfg.S3ForcePathStyle || cfg.S3AccessKeyID != "k" {
		t.Fatalf("legacy: %+v", cfg)
	}
}

func TestRefusals(t *testing.T) {
	tooMany := make([]string, MaxCells+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("us-east-%d", i+1)
	}
	cases := map[string]string{
		"KY_CELLS":                    "",
		"TENANCY_INTERNAL_API_SECRET": "short",
		"VAULT_INTERNAL_API_URL":      "http://vault.example.com",
		"SYNC_WEBHOOK_SECRET":         "",
		"SSO_CLIENT_SECRET":           "",
		"ORG_POLL_INTERVAL":           "soon",
		"TENANCY_RECONCILE_FROM_ZERO": "yes please",
		"DATABASE_URL":                "mysql://x",
	}
	for k, v := range cases {
		t.Run(k, func(t *testing.T) {
			setBase(t)
			t.Setenv(k, v)
			if _, err := LoadFromEnv(); err == nil {
				t.Fatalf("%s=%q accepted", k, v)
			}
		})
	}
	for _, badCells := range []string{
		"EU-WEST-1",
		"a",
		"1cell",
		"eu-west-1,eu-west-1",
		"eu-west-1,",
		"../escape",
		strings.Repeat("a", 33),
		strings.Join(tooMany, ","),
	} {
		t.Run("KY_CELLS/"+badCells, func(t *testing.T) {
			setBase(t)
			t.Setenv("KY_CELLS", badCells)
			if _, err := LoadFromEnv(); err == nil {
				t.Fatalf("KY_CELLS=%q accepted", badCells)
			}
		})
	}
	setBase(t)
	t.Setenv("ATTACHMENTS_FOLDER", "s3://b/a")
	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("s3 root without credentials accepted")
	}
}

func TestValidateInternalURL(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:8000", "http://localhost:8000", "http://vault:8000", "http://10.0.0.5", "https://vault.example.com"} {
		if err := ValidateInternalURL(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://vault.example.com", "ftp://vault", "http://u:p@vault", "vault:8000", "http://vault?x=1"} {
		if ValidateInternalURL(bad) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
