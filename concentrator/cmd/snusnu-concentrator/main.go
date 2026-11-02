package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/server"
	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

func main() {
	if err := run(); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func run() (runErr error) {
	addr := flag.String("listen", env("SNUSNU_LISTEN", ":8080"), "HTTP listen address (host:port or :port for all interfaces)")
	promote := flag.String("promote-email", "", "promote a verified user to admin and exit")
	resetMFA := flag.String("reset-mfa-email", "", "clear a user's MFA factors and sessions, then exit")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	driver := env("SNUSNU_DB_DRIVER", "sqlite")
	dsn := env("SNUSNU_DB_DSN", "snusnu.db")
	db, err := store.Open(ctx, driver, dsn)
	if err != nil {
		return err
	}
	defer func() {
		if err := db.DB.Close(); err != nil && runErr == nil {
			runErr = fmt.Errorf("close database: %w", err)
		}
	}()
	if *promote != "" {
		res, err := db.Exec(ctx, "UPDATE users SET role='admin' WHERE email=? AND verified_at>0", *promote)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return errors.New("verified user not found")
		}
		log.Printf("promoted %s to admin", *promote)
		return nil
	}
	if *resetMFA != "" {
		if err := db.ResetMFA(ctx, *resetMFA); err != nil {
			return err
		}
		log.Printf("reset MFA and sessions for %s", *resetMFA)
		return nil
	}
	instanceID := store.RandomUUID()
	if err := db.AcquireInstance(ctx, instanceID); err != nil {
		return err
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := db.ReleaseInstance(releaseCtx, instanceID); err != nil {
			if runErr == nil {
				runErr = fmt.Errorf("release instance lease: %w", err)
			} else {
				log.Printf("release instance lease: %v", err)
			}
		}
	}()
	if err := db.ResetLiveState(ctx); err != nil {
		return err
	}
	key, err := hex.DecodeString(os.Getenv("SNUSNU_MFA_KEY"))
	if err != nil || len(key) != 32 {
		return errors.New("SNUSNU_MFA_KEY must be 64 hex characters")
	}
	app, err := server.NewApp(db, server.Config{Origin: env("SNUSNU_ORIGIN", "http://localhost:8080"), Development: os.Getenv("SNUSNU_DEV") == "1", MFAKey: key, MetricsKey: os.Getenv("SNUSNU_METRICS_KEY"), SMTPAddr: os.Getenv("SNUSNU_SMTP_ADDR"), SMTPFrom: os.Getenv("SNUSNU_SMTP_FROM"), SMTPUser: os.Getenv("SNUSNU_SMTP_USER"), SMTPPassword: os.Getenv("SNUSNU_SMTP_PASSWORD"), CaptchaSiteKey: os.Getenv("SNUSNU_RECAPTCHA_SITE_KEY"), CaptchaSecret: os.Getenv("SNUSNU_RECAPTCHA_SECRET")})
	if err != nil {
		return err
	}
	if err := app.InitializeRouterPolicy(ctx); err != nil {
		return err
	}
	app.StartMaintenance(ctx)
	app.StartInstanceHeartbeat(ctx, instanceID)
	srv := server.New(*addr)
	srv.Handler = app.Handler()
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	var cause error
	serverDone := false
	select {
	case err := <-done:
		serverDone = true
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			cause = fmt.Errorf("serve HTTP: %w", err)
		}
	case <-ctx.Done():
	case err := <-app.Fatal():
		cause = err
		log.Printf("fatal concentrator condition: %v", err)
	}
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if clean := app.BeginDrain(drainCtx); !clean {
		log.Printf("router drain deadline exceeded; forcing process shutdown")
	}
	drainCancel()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP shutdown: %v", err)
		if cause == nil {
			cause = fmt.Errorf("HTTP shutdown: %w", err)
		}
	}
	cancel()
	backgroundCtx, backgroundCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := app.ShutdownBackground(backgroundCtx); err != nil {
		log.Printf("background shutdown: %v; pending records discarded", err)
		if cause == nil {
			cause = fmt.Errorf("background shutdown: %w", err)
		}
	}
	backgroundCancel()
	if !serverDone {
		if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) && cause == nil {
			cause = fmt.Errorf("serve HTTP: %w", err)
		}
	}
	return cause
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
