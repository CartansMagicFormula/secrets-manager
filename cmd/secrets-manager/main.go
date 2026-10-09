// secrets-manager: the fleet's thin vault (Go standard library only).
//
// Configuration (environment):
//
//	DATA_DIR              encrypted state + audit log, default /data
//	LISTEN_ADDR           TLS listener for clients and admin, default :8443
//	ADMIN_HTTP_ADDR       DEV ONLY: plain-HTTP admin listener (UI + admin API, no
//	                      client endpoints), publish on 127.0.0.1 only; default off
//	COOKIE_SECURE         "false" only for the plain-HTTP dev admin listener, default true
//	GRACE_PERIOD          previous version readable after a change, default 24h
//	ACCESS_TTL            lifetime of a client access token, default 1h (renewable)
//	ACCESS_MAX            maximum lifetime incl. renewals, default 24h
//	SERVER_NAMES          names in the vault's TLS certificate, default secrets-manager,localhost,127.0.0.1
//	CA_EXPORT_DIR         directory for the public CA certificate (fleet-ca.crt), default off
//	ENVIRONMENT           dev | staging | production (one vault per environment), default dev
//	AUTO_UNSEAL_KEY_FILE  DEV ONLY: unseal at start from this file (weaker: key on the same host)
//
// Subcommands: healthcheck; admin … (scripted setup, see admin.go).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
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

// healthcheck probes /health on the TLS listener. It skips certificate
// verification on purpose: it only checks liveness on loopback and sends nothing.
func healthcheck() int {
	client := http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
	}}
	resp, err := client.Get("https://127.0.0.1" + env("LISTEN_ADDR", ":8443") + "/health")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func durationEnv(logger *slog.Logger, name, fallback string) time.Duration {
	d, err := time.ParseDuration(env(name, fallback))
	if err != nil || d <= 0 {
		logger.Error("invalid duration", "setting", name)
		os.Exit(1)
	}
	return d
}

func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		if err := runAdmin(newLoopbackClient(), os.Args[2:], os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	var names []string
	if v := os.Getenv("SERVER_NAMES"); v != "" {
		names = strings.Split(v, ",")
	}
	srv, err := server.New(server.Config{
		DataDir:      env("DATA_DIR", "/data"),
		CookieSecure: env("COOKIE_SECURE", "true") != "false",
		GracePeriod:  durationEnv(logger, "GRACE_PERIOD", "24h"),
		AccessTTL:    durationEnv(logger, "ACCESS_TTL", "1h"),
		AccessMax:    durationEnv(logger, "ACCESS_MAX", "24h"),
		ServerNames:  names,
		CAExportDir:  os.Getenv("CA_EXPORT_DIR"),
		Environment:  os.Getenv("ENVIRONMENT"),
		Logger:       logger,
		UI:           web.Files,
	})
	if err != nil {
		logger.Error("cannot start", "error", err.Error())
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
	tlsConfig, err := srv.TLSConfig()
	if err != nil {
		logger.Error("TLS setup failed", "error", err.Error())
		os.Exit(1)
	}
	tlsSrv := newHTTPServer(env("LISTEN_ADDR", ":8443"), srv.Handler())
	tlsSrv.TLSConfig = tlsConfig
	servers := []*http.Server{tlsSrv}
	var adminSrv *http.Server
	if addr := os.Getenv("ADMIN_HTTP_ADDR"); addr != "" {
		adminSrv = newHTTPServer(addr, server.AdminOnly(srv.Handler()))
		servers = append(servers, adminSrv)
		logger.Warn("plain-HTTP admin listener enabled: development only", "addr", addr)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	errs := make(chan error, len(servers))
	go func() { errs <- tlsSrv.ListenAndServeTLS("", "") }()
	if adminSrv != nil {
		go func() { errs <- adminSrv.ListenAndServe() }()
	}
	logger.Info("secrets-manager listening (sealed until unsealed)", "addr", tlsSrv.Addr)
	select {
	case <-ctx.Done():
	case err := <-errs:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "error", err.Error())
			os.Exit(1)
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}
}
