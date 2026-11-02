package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/qa"
	"github.com/friedkiwi/snusnu/concentrator/internal/server"
	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

func main() {
	listenDefault := os.Getenv("SNUSNU_LISTEN")
	if listenDefault == "" {
		listenDefault = ":8081"
	}
	addr := flag.String("listen", listenDefault, "QA HTTP listen address (host:port or :port for all interfaces)")
	origin := flag.String("origin", "http://localhost:8081", "QA public origin")
	aliceNetID := flag.String("alice-netid", "QAALICE", "NETID for the isolated Alice QA fixture")
	flag.Parse()
	if !store.ValidNetID(*aliceNetID) {
		log.Fatal("invalid Alice QA NETID")
	}
	qa.Accounts[1].NetID = *aliceNetID
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	db, path, err := createQAStore(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer db.DB.Close()
	if err = qa.Seed(ctx, db); err != nil {
		log.Fatal(err)
	}
	if err = db.ResetLiveState(ctx); err != nil {
		log.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		log.Fatal(err)
	}
	app, err := server.NewApp(db, server.Config{Origin: *origin, Development: true, MFAKey: key})
	if err != nil {
		log.Fatal(err)
	}
	if err := app.InitializeRouterPolicy(ctx); err != nil {
		log.Fatal(err)
	}
	if err := app.StartLocalSNA(ctx); err != nil {
		log.Fatal(err)
	}
	log.Printf("QA database: %s", path)
	log.Printf("QA accounts and router tokens: see concentrator/QA.md")
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
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			log.Fatal(err)
		}
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}
}

func createQAStore(ctx context.Context) (*store.Store, string, error) {
	// MkdirTemp creates a private, unique directory every time. The QA binary
	// never consults SNUSNU_DB_DRIVER or SNUSNU_DB_DSN.
	dir, err := os.MkdirTemp("", "snusnu-qa-")
	if err != nil {
		return nil, "", err
	}
	path := filepath.Join(dir, "qa.sqlite")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, "", err
	}
	if err = file.Close(); err != nil {
		return nil, "", err
	}
	db, err := store.Open(ctx, "sqlite", path)
	return db, path, err
}
