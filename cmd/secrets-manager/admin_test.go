package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"secrets-manager/internal/server"
)

// vault: a fresh, uninitialized vault over TLS and an admin client for it.
func vault(t *testing.T) (*adminClient, func() *adminClient) {
	srv, err := server.New(server.Config{
		DataDir: t.TempDir(), CookieSecure: true, Environment: "dev",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := srv.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.Listener = tls.NewListener(ts.Listener, cfg)
	ts.Start()
	t.Cleanup(ts.Close)
	fresh := func() *adminClient { // one process per command, like fleet.sh
		jar, _ := cookiejar.New(nil)
		return &adminClient{base: strings.Replace(ts.URL, "http://", "https://", 1), http: &http.Client{Jar: jar, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		}}}
	}
	return fresh(), fresh
}

func run(t *testing.T, c *adminClient, stdin string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runAdmin(c, args, strings.NewReader(stdin), &out)
	return out.String(), err
}

const list = `{"environment":"dev",
  "secrets":[{"path":"svc/db-password","kind":"generated"},{"path":"svc/api-key","kind":"static"}],
  "clients":[{"name":"svc-app","policies":["svc/db-password"],"pki_names":[]},
             {"name":"svc-db","policies":["svc"],"pki_names":["svc-db"]}]}`

func TestAdminFlow(t *testing.T) {
	c, fresh := vault(t)
	password := "a very long passphrase\n"

	if out, err := run(t, c, "", "status"); err != nil || out != "initialized=false sealed=true environment=dev\n" {
		t.Fatalf("status: %q %v", out, err)
	}
	if _, err := run(t, c, "", "init", "-user", "commander"); err == nil {
		t.Fatal("init without a password on stdin")
	}
	master, err := run(t, c, password, "init", "-user", "commander")
	if err != nil || len(strings.TrimSpace(master)) < 40 {
		t.Fatalf("init: %v", err)
	}
	if _, err := run(t, fresh(), password, "init", "-user", "commander"); err == nil {
		t.Fatal("second init accepted")
	}

	// Seal (as the UI would), then unseal with the key from stdin
	if err := c.login("commander", "a very long passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := c.call("POST", "/v1/sys/seal", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, fresh(), "not-the-key\n", "unseal"); err == nil {
		t.Fatal("wrong master key accepted")
	}
	if _, err := run(t, fresh(), master, "unseal"); err != nil {
		t.Fatalf("unseal: %v", err)
	}

	// Apply: wrong password refused, then the report lists what was created
	if _, err := run(t, fresh(), "wrong password!!\n"+list, "apply", "-user", "commander"); err == nil {
		t.Fatal("apply with a wrong password")
	}
	out, err := run(t, fresh(), password+list, "apply", "-user", "commander")
	if err != nil || !strings.Contains(out, "created_clients: svc-app svc-db\n") ||
		!strings.Contains(out, "created_secrets: svc/db-password\n") || !strings.Contains(out, "missing_static: svc/api-key\n") {
		t.Fatalf("apply: %q %v", out, err)
	}
	if strings.Contains(out, "smt_") || strings.Contains(out, master) {
		t.Fatal("apply printed a secret")
	}

	// Enroll: unknown names give no codes at all; known ones give one code each
	if out, err := run(t, fresh(), password, "enroll", "-user", "commander", "svc-app", "nope"); err == nil || out != "" {
		t.Fatalf("enroll with unknown client: %q %v", out, err)
	}
	out, err = run(t, fresh(), password, "enroll", "-user", "commander", "svc-db", "svc-app", "svc-app")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if err != nil || len(lines) != 2 || !strings.HasPrefix(lines[0], "svc-app sme_") || !strings.HasPrefix(lines[1], "svc-db sme_") {
		t.Fatalf("enroll: %q %v", out, err)
	}
	// The code works once at the client endpoint and yields a start token
	code := strings.Fields(lines[0])[1]
	req, _ := http.NewRequest("POST", c.base+"/v1/auth/enroll", nil)
	req.Header.Set("Authorization", "Bearer "+code)
	resp, err := c.http.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("exchange: %v", err)
	}
	resp.Body.Close()
}
