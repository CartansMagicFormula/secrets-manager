// secrets-manager: the fleet's thin vault (Go standard library only).
//
// Configuration (environment):
//
//	DATA_DIR              encrypted state + audit log, default /data
//	LISTEN_ADDR           default :8200
//	COOKIE_SECURE         "false" only for plain-HTTP development, default true
//	GRACE_PERIOD          previous version readable after a change, default 24h
//	AUTO_UNSEAL_KEY_FILE  DEV ONLY: unseal at start from this file (weaker: key on the same host)
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"secrets-manager/internal/crypto"
	"secrets-manager/internal/server"
	"secrets-manager/web"
)

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func healthcheck() int {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1" + env("LISTEN_ADDR", ":8200") + "/health")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	grace, err := time.ParseDuration(env("GRACE_PERIOD", "24h"))
	if err != nil {
		logger.Error("invalid GRACE_PERIOD")
		os.Exit(1)
	}
	srv, err := server.New(server.Config{
		DataDir:      env("DATA_DIR", "/data"),
		CookieSecure: env("COOKIE_SECURE", "true") != "false",
		GracePeriod:  grace,
		Logger:       logger,
		UI:           web.Files,
	})
	if err != nil {
		logger.Error("cannot open data dir", "error", err.Error())
		os.Exit(1)
	}
	if path := os.Getenv("AUTO_UNSEAL_KEY_FILE"); path != "" {
		raw, err := os.ReadFile(path)
		key, kerr := crypto.DecodeKey(strings.TrimSpace(string(raw)))
		if err != nil || kerr != nil || srv.Unseal(key) != nil {
			logger.Error("auto-unseal failed (dev only); starting sealed")
		} else {
			logger.Warn("auto-unsealed from key file: development only")
		}
	}
	httpSrv := &http.Server{
		Addr:              env("LISTEN_ADDR", ":8200"),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdown)
	}()
	logger.Info("secrets-manager listening (sealed until unsealed)", "addr", httpSrv.Addr)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server stopped", "error", err.Error())
		os.Exit(1)
	}
}
