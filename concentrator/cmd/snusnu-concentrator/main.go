package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
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
	addr := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	promote := flag.String("promote-email", "", "promote a verified user to admin and exit")
	resetMFA := flag.String("reset-mfa-email", "", "clear a user's MFA factors and sessions, then exit")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	driver := env("SNUSNU_DB_DRIVER", "sqlite")
	dsn := env("SNUSNU_DB_DSN", "snusnu.db")
	db, err := store.Open(ctx, driver, dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.DB.Close()
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := db.Prune(ctx); err != nil {
					log.Printf("database cleanup: %v", err)
				}
			}
		}
	}()
	if *promote != "" {
		res, err := db.Exec(ctx, "UPDATE users SET role='admin' WHERE email=? AND verified_at>0", *promote)
		if err != nil {
			log.Fatal(err)
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			log.Fatal("verified user not found")
		}
		log.Printf("promoted %s to admin", *promote)
		return
	}
	if *resetMFA != "" {
		if err := db.ResetMFA(ctx, *resetMFA); err != nil {
			log.Fatal(err)
		}
		log.Printf("reset MFA and sessions for %s", *resetMFA)
		return
	}
	if err := db.ResetLiveState(ctx); err != nil {
		log.Fatal(err)
	}
	key, err := hex.DecodeString(os.Getenv("SNUSNU_MFA_KEY"))
	if err != nil || len(key) != 32 {
		log.Fatal("SNUSNU_MFA_KEY must be 64 hex characters")
	}
	app, err := server.NewApp(db, server.Config{Origin: env("SNUSNU_ORIGIN", "http://localhost:8080"), Development: os.Getenv("SNUSNU_DEV") == "1", MFAKey: key, SMTPAddr: os.Getenv("SNUSNU_SMTP_ADDR"), SMTPFrom: os.Getenv("SNUSNU_SMTP_FROM"), SMTPUser: os.Getenv("SNUSNU_SMTP_USER"), SMTPPassword: os.Getenv("SNUSNU_SMTP_PASSWORD"), CaptchaSiteKey: os.Getenv("SNUSNU_RECAPTCHA_SITE_KEY"), CaptchaSecret: os.Getenv("SNUSNU_RECAPTCHA_SECRET")})
	if err != nil {
		log.Fatal(err)
	}
	srv := server.New(*addr)
	srv.Handler = app.Handler()
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Fatal(err)
		}
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
