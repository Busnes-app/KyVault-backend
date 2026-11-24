package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Busnes-app/ky-primitives/oidcverify"
	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kyvault-worker/internal/config"
	"github.com/Busnes-app/kyvault-worker/internal/s3clean"
	"github.com/Busnes-app/kyvault-worker/internal/server"
	"github.com/Busnes-app/kyvault-worker/internal/state"
	"github.com/Busnes-app/kyvault-worker/internal/syncer"
	"github.com/Busnes-app/kyvault-worker/internal/vaultapi"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	if err := run(logger); err != nil {
		logger.Error("worker stopped", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	for _, w := range cfg.Warnings {
		logger.Warn("configuration adjusted", "detail", w)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	st, err := state.OpenPostgres(ctx, pool)
	if err != nil {
		return err
	}

	vault, err := vaultapi.New(cfg.VaultAPIURL, cfg.InternalSecret, nil)
	if err != nil {
		return err
	}
	s3 := s3clean.Client{
		Endpoint: cfg.S3Endpoint, Region: cfg.S3Region, ForcePathStyle: cfg.S3ForcePathStyle,
		AccessKeyID: cfg.S3AccessKeyID, SecretAccessKey: cfg.S3SecretAccessKey,
	}
	attachments, err := s3clean.ForRoot(cfg.AttachmentsRoot, s3)
	if err != nil {
		return fmt.Errorf("ATTACHMENTS_FOLDER: %w", err)
	}
	sends, err := s3clean.ForRoot(cfg.SendsRoot, s3)
	if err != nil {
		return fmt.Errorf("SENDS_FOLDER: %w", err)
	}
	if attachments == nil || sends == nil {
		logger.Error("storage roots incomplete: set DATA_FOLDER, or ATTACHMENTS_FOLDER and SENDS_FOLDER; cleanup items will stay pending")
	}

	syn := &syncer.Syncer{
		Directory:          &suitedir.Client{Issuer: cfg.KyIdentityURL, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret},
		Vault:              vault,
		State:              st,
		Cells:              cfg.Cells,
		Issuer:             cfg.OIDCIssuer,
		StorageWantBytes:   cfg.StorageWantBytes,
		StorageRenewBefore: cfg.StorageRenewBefore,
		Attachments:        attachments,
		Sends:              sends,
		Logger:             logger,
	}
	srv := &server.Server{
		Issuer:            cfg.OIDCIssuer,
		SyncWebhookSecret: []byte(cfg.SyncWebhookSecret),
		LogoutVerifier:    &oidcverify.Verifier{Issuer: cfg.OIDCIssuer, Audience: cfg.ClientID, JWKSURL: cfg.OIDCJWKSURL},
		State:             st,
		Vault:             vault,
		TriggerCleanup:    syn.TriggerCleanup,
		Logger:            logger,
	}

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdown)
	}()
	go startSync(ctx, logger, cfg, syn, st, srv)

	logger.Info("kyvault-worker listening", "addr", cfg.ListenAddr, "cells", cfg.Cells)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// startSync reconciles org and erased-subject state before the worker reports ready,
// retrying until it succeeds, then starts the periodic loops.
func startSync(ctx context.Context, logger *slog.Logger, cfg config.Config, syn *syncer.Syncer, st state.Store, srv *server.Server) {
	retry := time.NewTicker(5 * time.Second)
	defer retry.Stop()
	for {
		err := syn.Reconcile(ctx, cfg.ReconcileFromZero)
		if err == nil {
			break
		}
		logger.Error("initial reconciliation failed; not ready", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-retry.C:
		}
	}
	srv.SetReady()
	logger.Info("reconciled with KyIdentity; ready", "from_zero", cfg.ReconcileFromZero)

	go syncer.Loop(ctx, logger, "orgs", cfg.OrgPollInterval, func(c context.Context) error { return syn.SyncOrgs(c, false) })
	go syncer.Loop(ctx, logger, "erased", cfg.ErasedPollInterval, func(c context.Context) error { return syn.SyncErased(c, false) })
	go syncer.Loop(ctx, logger, "storage", cfg.StorageInterval, syn.ReportStorage)
	go syncer.Loop(ctx, logger, "prune", cfg.PruneInterval, func(c context.Context) error {
		_, err := st.Prune(c, time.Now())
		return err
	})
	if err := syn.ReportStorage(ctx); err != nil {
		logger.Warn("background loop failed", "loop", "storage", "err", err)
	}
	syn.RunCleanup(ctx, cfg.CleanupInterval)
}
