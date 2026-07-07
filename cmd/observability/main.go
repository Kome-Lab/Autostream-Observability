package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/example/autostream-observability/internal/auth"
	"github.com/example/autostream-observability/internal/control"
	"github.com/example/autostream-observability/internal/database"
	"github.com/example/autostream-observability/internal/httpapi"
	"github.com/example/autostream-observability/internal/store"
	"github.com/example/autostream-observability/internal/version"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Printf("autostream-observability %s\ncommit: %s\nbuild_date: %s\n", version.Current(), version.Commit, version.BuildDate)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "configure" {
		if err := control.RunConfigureCommand(os.Args[2:], control.ServiceType, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "configure failed: %v\n", err)
			os.Exit(2)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	addr := os.Getenv("OBSERVABILITY_BIND_ADDR")
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
	go runControlPanelRegistrationLoop(ctx)
	ingestVerifier := auth.Verifier{}
	adminVerifier := auth.Verifier{}
	if nodeToken := control.NodeRuntimeTokenFromEnv(); nodeToken != "" {
		adminVerifier = auth.WithRawTokenScopes(adminVerifier, nodeToken, "*")
	}
	log.Printf("autostream-observability listening on %s", addr)
	server := &http.Server{
		Addr:              addr,
		Handler:           httpapi.NewServerWithStoreAuthz("observability", st, ingestVerifier, adminVerifier),
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

func runControlPanelRegistrationLoop(ctx context.Context) {
	lastState := ""
	registeredServiceID := ""
	for {
		client := control.FromEnv()
		wait := controlPanelRegistrationInterval(client)
		state := ""
		switch {
		case strings.TrimSpace(client.ConfigError) != "":
			state = "invalid:" + client.ConfigError
			logRegistrationStateChange(&lastState, state, "node config invalid: %v", client.ConfigError)
		case !client.Enabled():
			if control.NodeConfigPendingFromEnv() {
				state = "pending:" + control.NodeConfigPathFromEnv()
				logRegistrationStateChange(&lastState, state, "node config pending: waiting for %s", control.NodeConfigPathFromEnv())
			} else {
				state = "disabled"
				logRegistrationStateChange(&lastState, state, "control panel registration is not configured; waiting for AUTOSTREAM_NODE_CONFIG")
			}
			registeredServiceID = ""
		case strings.TrimSpace(client.ServicePublicURL) == "":
			state = "missing-public-url:" + client.ServiceID
			logRegistrationStateChange(&lastState, state, "node config invalid: missing api.host or api.port")
			registeredServiceID = ""
		default:
			if registeredServiceID != client.ServiceID {
				if err := client.Register(ctx); err != nil {
					state = "register-failed:" + err.Error()
					logRegistrationStateChange(&lastState, state, "control panel registration failed: %v", err)
					registeredServiceID = ""
					break
				}
				registeredServiceID = client.ServiceID
				state = "registered:" + client.ServiceID
				logRegistrationStateChange(&lastState, state, "registered with control panel as %s", client.ServiceID)
			}
			if registeredServiceID == client.ServiceID {
				if err := client.Heartbeat(ctx); err != nil {
					state = "heartbeat-failed:" + err.Error()
					logRegistrationStateChange(&lastState, state, "control panel heartbeat failed: %v", err)
				} else {
					lastState = "online:" + client.ServiceID
				}
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func controlPanelRegistrationInterval(client control.Client) time.Duration {
	if client.Enabled() && client.HeartbeatEvery > 0 {
		return client.HeartbeatEvery
	}
	return 10 * time.Second
}

func logRegistrationStateChange(lastState *string, state, format string, args ...any) {
	if state == *lastState {
		return
	}
	log.Printf(format, args...)
	*lastState = state
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
