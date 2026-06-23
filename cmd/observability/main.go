package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/autostream-observability/internal/control"
	"github.com/example/autostream-observability/internal/database"
	"github.com/example/autostream-observability/internal/httpapi"
	"github.com/example/autostream-observability/internal/store"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	addr := os.Getenv("AUTOSTREAM_BIND_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	if os.Getenv("DATABASE_URL") == "" {
		log.Fatal("DATABASE_URL is required; observability does not support production memory storage")
	}
	if os.Getenv("AUTOSTREAM_SECRET_ENCRYPTION_KEY") == "" {
		log.Fatal("AUTOSTREAM_SECRET_ENCRYPTION_KEY is required when DATABASE_URL is configured")
	}
	db, err := openDatabaseWithRetry(context.Background(), 60*time.Second, 2*time.Second)
	if err != nil {
		log.Fatalf("open mariadb failed: %v", err)
	}
	defer db.Close()
	setupCtx, cancelSetup := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelSetup()
	if err := database.RunEmbeddedMigrations(setupCtx, db); err != nil {
		log.Fatalf("run migrations failed: %v", err)
	}
	st := store.MariaDBStore{DB: db, SecretKey: os.Getenv("AUTOSTREAM_SECRET_ENCRYPTION_KEY")}
	controlClient := control.FromEnv()
	if controlClient.Enabled() && controlClient.ServicePublicURL != "" {
		if err := controlClient.Register(ctx); err != nil {
			log.Printf("control panel registration failed: %v", err)
		} else {
			log.Printf("registered with control panel as %s", controlClient.ServiceID)
		}
		go controlClient.RunHeartbeatLoop(ctx, func(err error) {
			log.Printf("control panel heartbeat failed: %v", err)
		})
	}
	log.Printf("autostream-observability listening on %s", addr)
	server := &http.Server{
		Addr:              addr,
		Handler:           httpapi.NewServerWithStore("observability", st),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("observability shutdown failed: %v", err)
		}
	}()
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func openDatabaseWithRetry(parent context.Context, timeout, interval time.Duration) (*sql.DB, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(parent, 10*time.Second)
		db, err := database.OpenFromEnv(ctx)
		cancel()
		if err == nil {
			if attempt > 1 {
				log.Printf("database connection succeeded after %d attempt(s)", attempt)
			}
			return db, nil
		}
		lastErr = err
		if time.Now().Add(interval).After(deadline) {
			return nil, lastErr
		}
		log.Printf("database is not ready yet (attempt %d): %v", attempt, err)
		time.Sleep(interval)
	}
}
