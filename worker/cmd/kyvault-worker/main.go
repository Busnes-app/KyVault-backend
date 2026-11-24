package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Busnes-app/ky-primitives/oidcverify"
	"github.com/Busnes-app/kyvault-worker/internal/config"
	"github.com/Busnes-app/kyvault-worker/internal/pubsub"
	"github.com/Busnes-app/kyvault-worker/internal/s3clean"
	"github.com/Busnes-app/kyvault-worker/internal/server"
	"github.com/Busnes-app/kyvault-worker/internal/store"
	"github.com/Busnes-app/kyvault-worker/internal/syncer"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.LoadFromEnv()
	if err != nil {
		logger.Error("invalid worker configuration", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("failed creating PostgreSQL pool", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		logger.Error("failed connecting to PostgreSQL", "err", err)
		os.Exit(1)
	}

	st := store.New(pool)
	pub := pubsub.NewPublisher(pool, cfg.NotifyChan, cfg.WorkerOrigin)

	var erasers []s3clean.Eraser
	if cfg.S3Bucket != "" {
		erasers = append(erasers, &s3clean.Client{
			Endpoint:        cfg.S3Endpoint,
			Bucket:          cfg.S3Bucket,
			Region:          cfg.S3Region,
			AccessKeyID:     cfg.S3AccessKeyID,
			SecretAccessKey: cfg.S3SecretAccessKey,
			ForcePathStyle:  cfg.S3ForcePathStyle,
			KeyPrefix:       cfg.S3Prefix,
		})
	}
	if cfg.LocalDataFolder != "" {
		erasers = append(erasers, &s3clean.LocalFSEraser{DataFolder: cfg.LocalDataFolder})
	}
	var eraser s3clean.Eraser
	if len(erasers) > 0 {
		eraser = &s3clean.MultiEraser{Erasers: erasers}
	}

	syn := &syncer.Syncer{
		BaseURL:    cfg.KyIdentityBaseURL,
		Token:      cfg.KyIdentityToken,
		HomeRegion: cfg.HomeRegion,
		Store:      st,
		Publisher:  pub,
		Eraser:     eraser,
		Logger:     logger,
	}

	var logoutVerifier server.LogoutVerifier
	if cfg.OIDCIssuer != "" && cfg.OIDCAudience != "" && cfg.OIDCJWKSURL != "" {
		logoutVerifier = &oidcverify.Verifier{
			Issuer:   cfg.OIDCIssuer,
			Audience: cfg.OIDCAudience,
			JWKSURL:  cfg.OIDCJWKSURL,
		}
	} else {
		logger.Warn("OIDC backchannel logout verifier disabled (SSO_AUTHORITY / SSO_CLIENT_ID / OIDC_JWKS_URL not fully set)")
	}

	srv := &server.Server{
		HomeRegion:        cfg.HomeRegion,
		SyncWebhookSecret: []byte(cfg.SyncWebhookSecret),
		LogoutVerifier:    logoutVerifier,
		Store:             st,
		Publisher:         pub,
		Syncer:            syn,
		Logger:            logger,
	}

	// Start background suite loops.
	go runLoop(ctx, logger, "org_entitlement_poll", cfg.OrgPollInterval, func(c context.Context) error {
		return syn.PollOrgs(c)
	})
	go runLoop(ctx, logger, "erasure_stream_poll", cfg.ErasedPollInterval, func(c context.Context) error {
		return syn.PollErased(c)
	})
	go runLoop(ctx, logger, "storage_metering_report", cfg.StorageReportInterval, func(c context.Context) error {
		return syn.ReportStorage(c)
	})
	go runLoop(ctx, logger, "prune_processed_events", cfg.PruneInterval, func(c context.Context) error {
		n, err := st.PruneExpiredEvents(c, time.Now().UTC().Unix())
		if err == nil && n > 0 {
			logger.Info("pruned expired processed events", "deleted", n)
		}
		return err
	})

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	logger.Info("kyvault-worker listening", "addr", cfg.ListenAddr, "home_region", cfg.HomeRegion, "notify_channel", cfg.NotifyChan)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("worker HTTP server error", "err", err)
		os.Exit(1)
	}
}

func runLoop(ctx context.Context, logger *slog.Logger, name string, interval time.Duration, fn func(context.Context) error) {
	if interval <= 0 {
		return
	}
	// Run once immediately on startup, then on every tick.
	if err := fn(ctx); err != nil && ctx.Err() == nil {
		logger.Warn("background loop error", "loop", name, "err", err)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := fn(ctx); err != nil && ctx.Err() == nil {
				logger.Warn("background loop error", "loop", name, "err", err)
			}
		}
	}
}
