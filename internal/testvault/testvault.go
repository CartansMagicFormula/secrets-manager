// Package testvault starts a real, throwaway vault over TLS for tests of the
// client and sm-agent (never used by production code).
package testvault

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"secrets-manager/internal/server"
)

// Vault under test.
type Vault struct {
	t       *testing.T
	Srv     *server.Server
	TS      *httptest.Server
	Dir     string
	CAFile  string
	cookie  string
	handler http.Handler
	Master  string
}

// Admin calls the admin API directly (no network), returning status and body.
func (v *Vault) Admin(method, path, body string) (int, map[string]any) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-Requested-With", "secrets-manager")
	if v.cookie != "" {
		req.AddCookie(&http.Cookie{Name: "sm_session", Value: v.cookie})
	}
	rec := httptest.NewRecorder()
	v.handler.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.Name == "sm_session" && c.Value != "" {
			v.cookie = c.Value
		}
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// Start initializes a vault, logs the admin in and serves it over TLS.
func Start(t *testing.T) *Vault {
	t.Helper()
	dir := t.TempDir()
	srv, err := server.New(server.Config{
		DataDir: dir, CAExportDir: dir, CookieSecure: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	v := &Vault{t: t, Srv: srv, Dir: dir, CAFile: filepath.Join(dir, "fleet-ca.crt"), handler: srv.Handler()}
	creds := `{"username":"commander","password":"a very long passphrase"}`
	code, out := v.Admin("POST", "/v1/sys/init", creds)
	if code != 201 {
		t.Fatalf("init: %d", code)
	}
	v.Master = out["master_key"].(string)
	if code, _ := v.Admin("POST", "/v1/admin/login", creds); code != 200 {
		t.Fatalf("admin login: %d", code)
	}
	cfg, err := srv.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	// Own TLS listener: StartTLS would add httptest's certificate and bypass ours
	v.TS = httptest.NewUnstartedServer(v.handler)
	v.TS.Listener = tls.NewListener(v.TS.Listener, cfg)
	v.TS.Start()
	v.TS.URL = strings.Replace(v.TS.URL, "http://", "https://", 1)
	t.Cleanup(v.TS.Close)
	return v
}

// Client creates a vault client and writes its start token to a file.
func (v *Vault) Client(name, body string) string {
	code, out := v.Admin("POST", "/v1/admin/clients", body)
	if code != 201 {
		v.t.Fatalf("create client: %d", code)
	}
	path := filepath.Join(v.t.TempDir(), name+".token")
	if err := os.WriteFile(path, []byte(out["token"].(string)+"\n"), 0o600); err != nil {
		v.t.Fatal(err)
	}
	return path
}
