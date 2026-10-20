package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-provisioner/internal/config"
	"github.com/openbasalt/samba-conductor-provisioner/internal/directory"
	"github.com/openbasalt/samba-conductor-provisioner/internal/secret"
	"github.com/openbasalt/samba-conductor-provisioner/internal/server"
	"github.com/openbasalt/samba-conductor-provisioner/internal/store"
)

// tokenRetention is how long closed tokens are kept (for token.list and
// the per-account daily limit).
const tokenRetention = 90 * 24 * time.Hour

// loadAccountPassword reads the "account-password" credential and keeps
// it sealed in memory; the plaintext is cleared at once.
func loadAccountPassword(cfg *config.Config) (*secret.Sealed, error) {
	pw, err := secret.Load(config.CredentialAccountPassword)
	if err != nil {
		return nil, fmt.Errorf("the account password: %w", err)
	}
	defer clear(pw)
	n := len(pw)
	for n > 0 && (pw[n-1] == '\n' || pw[n-1] == '\r') {
		n--
	}
	if n == 0 {
		return nil, fmt.Errorf("the account password credential %q is empty", config.CredentialAccountPassword)
	}
	return secret.Seal(pw[:n], []byte(strings.ToLower(cfg.Account.Username)))
}

func serve(cfgPath string, stderr io.Writer) int {
	log := newLogger(stderr)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Error("configuration", "err", err)
		return exitError
	}
	if len(cfg.Scope.OUs) == 0 {
		log.Warn("no scope OU is configured: every operation that names an account is refused")
	}
	ctx, cancel := signalContext()
	defer cancel()

	sealed, err := loadAccountPassword(cfg)
	if err != nil {
		log.Error("credentials", "err", err)
		return exitError
	}
	defer sealed.Close()
	raw, err := secret.Load(config.CredentialStateKey)
	if err != nil {
		log.Error("credentials", "err", err)
		return exitError
	}
	key, err := secret.ParseKey(raw)
	clear(raw)
	if err != nil {
		log.Error("credentials", "err", err)
		return exitError
	}
	auditKey := store.AuditKey(key)
	clear(key)
	st, err := store.Open(ctx, cfg.State.Database, auditKey)
	clear(auditKey)
	if err != nil {
		log.Error("state database", "err", err)
		return exitError
	}
	defer func() { _ = st.Close() }()

	dir, err := directory.NewAD(cfg, sealed, log)
	if err != nil {
		log.Error("directory", "err", err)
		return exitError
	}
	defer dir.Close()
	// A first sign-in shows configuration or delegation problems at start;
	// a failure is not fatal (the DCs may come up later).
	pctx, pcancel := context.WithTimeout(ctx, 30*time.Second)
	if who, err := dir.Ping(pctx); err != nil {
		log.Warn("the directory is not reachable yet", "err", err)
	} else {
		log.Info("signed in to the directory", "identity", who, "mechanism", dir.Mechanism())
	}
	pcancel()

	svc, err := server.NewService(server.Options{Config: cfg, Store: st, Directory: dir, Logger: log, Version: version})
	if err != nil {
		log.Error("service", "err", err)
		return exitError
	}
	ln, err := server.NewListener(svc, cfg.API, nil)
	if err != nil {
		log.Error("API", "err", err)
		return exitError
	}
	if err := ln.Listen(); err != nil {
		log.Error("API", "err", err)
		return exitError
	}
	go housekeeping(ctx, st, log)
	log.Info("conductor-provisioner serving", "version", version, "account", cfg.Account.Username, "scope_ous", len(cfg.Scope.OUs))
	if err := ln.Serve(ctx); err != nil {
		log.Error("API", "err", err)
		return exitError
	}
	return exitOK
}

// housekeeping marks expired tokens and prunes old closed ones hourly.
func housekeeping(ctx context.Context, st *store.Store, log interface {
	Warn(msg string, args ...any)
}) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if _, err := st.ExpireDue(ctx); err != nil && ctx.Err() == nil {
			log.Warn("expiring tokens failed", "err", err)
		}
		if _, err := st.Prune(ctx, time.Now().Add(-tokenRetention)); err != nil && ctx.Err() == nil {
			log.Warn("pruning tokens failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
