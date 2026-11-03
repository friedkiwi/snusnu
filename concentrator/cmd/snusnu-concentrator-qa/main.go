package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
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
	dbPath := flag.String("db", "", "reuse an existing private QA SQLite database instead of creating a fresh fixture")
	origin := flag.String("origin", "http://localhost:8081", "QA public origin")
	aliceNetID := flag.String("alice-netid", "QAALICE", "NETID for the isolated Alice QA fixture")
	printerProbe := flag.Bool("printer-probe", false, "advertise a QA-only SNUSNU.PRINTER wire trace endpoint")
	printerProbeDial := flag.String("printer-probe-dial", "", "make one outbound printer probe session attempt to NETID.LU")
	snaDebug := flag.Bool("sna-debug", false, "log SNA circuit state and protocol data to stderr")
	flag.Parse()
	if !store.ValidNetID(*aliceNetID) {
		log.Fatal("invalid Alice QA NETID")
	}
	qa.Accounts[1].NetID = *aliceNetID
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	db, path, fresh, err := openQAStore(ctx, *dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.DB.Close()
	if fresh {
		if err = qa.Seed(ctx, db); err != nil {
			log.Fatal(err)
		}
	}
	if err = db.ResetLiveState(ctx); err != nil {
		log.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		log.Fatal(err)
	}
	app, err := server.NewApp(db, server.Config{Origin: *origin, Development: true, SNADebug: *snaDebug, MFAKey: key, DataDir: filepath.Dir(path)})
	if err != nil {
		log.Fatal(err)
	}
	if err := app.InitializeRouterPolicy(ctx); err != nil {
		log.Fatal(err)
	}
	if *printerProbe {
		err = app.StartLocalSNAPrinterProbe(ctx)
	} else {
		err = app.StartLocalSNA(ctx)
	}
	if err != nil {
		log.Fatal(err)
	}
	if *printerProbeDial != "" {
		parts := strings.Split(*printerProbeDial, ".")
		if !*printerProbe || len(parts) != 2 || !store.ValidNetID(parts[0]) || !store.ValidNetID(parts[1]) {
			log.Fatal("-printer-probe-dial requires -printer-probe and NETID.LU")
		}
		app.DialLocalSNAPrinterProbe(ctx, parts[0], parts[1])
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

func openQAStore(ctx context.Context, existingPath string) (*store.Store, string, bool, error) {
	if existingPath == "" {
		db, path, err := createQAStore(ctx)
		return db, path, true, err
	}
	info, err := os.Stat(existingPath)
	if err != nil {
		return nil, "", false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, "", false, fmt.Errorf("QA database must be an existing private regular file")
	}
	db, err := store.Open(ctx, "sqlite", existingPath)
	return db, existingPath, false, err
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
