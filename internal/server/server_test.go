package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type harness struct {
	t      *testing.T
	srv    *Server
	h      http.Handler
	cookie string
	dir    string
	now    time.Time
}

func newHarness(t *testing.T) *harness {
	dir := t.TempDir()
	hs := &harness{t: t, dir: dir, now: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)}
	srv, err := New(Config{
		DataDir: dir, CookieSecure: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return hs.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	hs.srv, hs.h = srv, srv.Handler()
	return hs
}

func (hs *harness) do(method, path, body string, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if method != "GET" {
		req.Header.Set(csrfHeader, csrfValue)
	}
	if hs.cookie != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: hs.cookie})
	}
	for k, v := range header {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %d: %s", rec.Code, rec.Body)
	}
	return out
}

const adminBody = `{"username":"commander","password":"a very long passphrase"}`

func (hs *harness) initAndLogin() string {
	rec := hs.do("POST", "/v1/sys/init", adminBody, nil)
	if rec.Code != 201 {
		hs.t.Fatalf("init: %d %s", rec.Code, rec.Body)
	}
	master := decode(hs.t, rec)["master_key"].(string)
	hs.login()
	return master
}

func (hs *harness) login() {
	rec := hs.do("POST", "/v1/admin/login", adminBody, nil)
	if rec.Code != 200 {
		hs.t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
				hs.t.Fatal("session cookie not hardened")
			}
			hs.cookie = c.Value
		}
	}
}

// clientLogin exchanges a start token for an access token.
func (hs *harness) clientLogin(start, instance string) string {
	rec := hs.do("POST", "/v1/auth/login", `{"instance":"`+instance+`"}`, map[string]string{"Authorization": "Bearer " + start})
	if rec.Code != 200 {
		hs.t.Fatalf("client login: %d %s", rec.Code, rec.Body)
	}
	return decode(hs.t, rec)["access_token"].(string)
}

func TestFullFlow(t *testing.T) {
	hs := newHarness(t)
	if s := decode(t, hs.do("GET", "/v1/sys/status", "", nil)); s["initialized"] != false || s["sealed"] != true {
		t.Fatalf("status before init: %v", s)
	}
	master := hs.initAndLogin()
	if hs.do("POST", "/v1/sys/init", adminBody, nil).Code != 409 {
		t.Fatal("re-init allowed")
	}

	// Static secret + generated secret
	if rec := hs.do("PUT", "/v1/admin/secrets/llm-gateway/anthropic", `{"kind":"static","value":"sk-ant-123","note":"prod key"}`, nil); rec.Code != 200 {
		t.Fatalf("put static: %d %s", rec.Code, rec.Body)
	}
	rec := hs.do("PUT", "/v1/admin/secrets/osiris/analyzer-token", `{"kind":"generated","alphabet":"alnum","length":40}`, nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "value") {
		t.Fatalf("put generated must not return the value: %d %s", rec.Code, rec.Body)
	}
	list := hs.do("GET", "/v1/admin/secrets", "", nil).Body.String()
	if strings.Contains(list, "sk-ant-123") {
		t.Fatal("list leaks values")
	}

	// Client with a policy for llm-gateway only
	rec = hs.do("POST", "/v1/admin/clients", `{"name":"llm-gateway","policies":["llm-gateway"]}`, nil)
	if rec.Code != 201 {
		t.Fatalf("client: %d %s", rec.Code, rec.Body)
	}
	start := decode(t, rec)["token"].(string)
	read := func(path, tok string) *httptest.ResponseRecorder {
		return hs.do("GET", "/v1/secrets/"+path, "", map[string]string{"Authorization": "Bearer " + tok})
	}
	if read("llm-gateway/anthropic", start).Code != 401 {
		t.Fatal("start token reads secrets directly (must only log in)")
	}
	token := hs.clientLogin(start, "llm-gateway-1")
	if got := decode(t, read("llm-gateway/anthropic", token)); got["value"] != "sk-ant-123" || got["version"] != float64(1) {
		t.Fatalf("client read: %v", got)
	}
	if read("osiris/analyzer-token", token).Code != 403 || read("llm-gateway/missing", token).Code != 403 {
		t.Fatal("policy not enforced (or existence leaked)")
	}
	if read("llm-gateway/anthropic", "sma_wrong").Code != 401 {
		t.Fatal("wrong token accepted")
	}

	// Rotation keeps the previous version readable during the grace period
	osirisStart := decode(t, hs.do("POST", "/v1/admin/clients", `{"name":"osiris-hub","policies":["osiris"]}`, nil))["token"].(string)
	osiris := hs.clientLogin(osirisStart, "osiris-hub-1")
	first := decode(t, read("osiris/analyzer-token", osiris))["value"].(string)
	if hs.do("POST", "/v1/admin/rotate/osiris/analyzer-token", "", nil).Code != 200 {
		t.Fatal("rotate")
	}
	second := decode(t, read("osiris/analyzer-token", osiris))
	if second["value"] == first || second["version"] != float64(2) || len(second["value"].(string)) != 40 {
		t.Fatalf("rotation: %v", second)
	}
	if decode(t, read("osiris/analyzer-token?version=previous", osiris))["value"] != first {
		t.Fatal("previous version not readable in grace period")
	}
	hs.now = hs.now.Add(25 * time.Hour)
	if read("osiris/analyzer-token", osiris).Code != 401 {
		t.Fatal("access token valid after its lifetime")
	}
	osiris = hs.clientLogin(osirisStart, "osiris-hub-1")
	if read("osiris/analyzer-token?version=previous", osiris).Code != 404 {
		t.Fatal("previous version readable after grace period")
	}
	hs.login() // the admin session expired during the time jump
	if hs.do("POST", "/v1/admin/rotate/llm-gateway/anthropic", "", nil).Code != 409 {
		t.Fatal("static secret rotated")
	}

	// Reveal (audited), revoke
	if decode(t, hs.do("POST", "/v1/admin/reveal/llm-gateway/anthropic", "", nil))["value"] != "sk-ant-123" {
		t.Fatal("reveal")
	}
	clients := []map[string]any{}
	_ = json.Unmarshal(hs.do("GET", "/v1/admin/clients", "", nil).Body.Bytes(), &clients)
	token = hs.clientLogin(start, "llm-gateway-1")
	for _, c := range clients {
		if c["name"] == "llm-gateway" {
			hs.do("DELETE", "/v1/admin/clients/"+c["id"].(string), "", nil)
		}
	}
	if read("llm-gateway/anthropic", token).Code != 401 {
		t.Fatal("revoked client can read")
	}
	if hs.do("POST", "/v1/auth/login", `{"instance":"x"}`, map[string]string{"Authorization": "Bearer " + start}).Code != 401 {
		t.Fatal("revoked client can log in")
	}

	// Seal: everything refused; unseal with the master key restores state
	if hs.do("POST", "/v1/sys/seal", "", nil).Code != 200 {
		t.Fatal("seal")
	}
	if read("osiris/analyzer-token", osiris).Code != 503 || hs.do("GET", "/v1/admin/secrets", "", nil).Code != 503 {
		t.Fatal("sealed vault answers")
	}
	if hs.do("POST", "/v1/sys/unseal", `{"master_key":"AAAA"}`, nil).Code != 400 {
		t.Fatal("bad key accepted")
	}
	if hs.do("POST", "/v1/sys/unseal", `{"master_key":"`+master+`"}`, nil).Code != 200 {
		t.Fatal("unseal")
	}
	if hs.do("GET", "/v1/admin/secrets", "", nil).Code != 401 {
		t.Fatal("session survived sealing")
	}
	hs.login()
	if read("osiris/analyzer-token", osiris).Code != 401 {
		t.Fatal("access token survived sealing")
	}
	osiris = hs.clientLogin(osirisStart, "osiris-hub-1")
	if decode(t, read("osiris/analyzer-token", osiris))["version"] != float64(2) {
		t.Fatal("state lost across seal/unseal")
	}

	// Nothing secret on disk or in the audit log
	for _, name := range []string{"state.json", "audit.log"} {
		raw, _ := os.ReadFile(filepath.Join(hs.dir, name))
		if strings.Contains(string(raw), "sk-ant-123") || strings.Contains(string(raw), first) || strings.Contains(string(raw), token) || strings.Contains(string(raw), start) {
			t.Fatalf("%s contains a secret value", name)
		}
	}
	verify := decode(t, hs.do("GET", "/v1/admin/audit/verify", "", nil))
	if verify["ok"] != true || verify["entries"].(float64) < 10 {
		t.Fatalf("audit verify: %v", verify)
	}
}

func TestAdminProtection(t *testing.T) {
	hs := newHarness(t)
	hs.initAndLogin()
	// CSRF header required on state changes
	if hs.do("PUT", "/v1/admin/secrets/a/b", `{"kind":"static","value":"x"}`, map[string]string{csrfHeader: ""}).Code != 403 {
		t.Fatal("missing CSRF header accepted")
	}
	// No session → 401
	hs.cookie = ""
	if hs.do("GET", "/v1/admin/secrets", "", nil).Code != 401 {
		t.Fatal("no session accepted")
	}
	if hs.do("GET", "/v1/admin/secrets", "", map[string]string{"Cookie": sessionCookie + "=forged"}).Code != 401 {
		t.Fatal("forged session accepted")
	}
	// Brute force: 5 attempts per minute, generic message
	for i := 0; i < 5; i++ {
		rec := hs.do("POST", "/v1/admin/login", `{"username":"commander","password":"wrong-password-123"}`, nil)
		if rec.Code != 401 || !strings.Contains(rec.Body.String(), "invalid username or password") {
			t.Fatalf("attempt %d: %d", i, rec.Code)
		}
	}
	if rec := hs.do("POST", "/v1/admin/login", adminBody, nil); rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("rate limit: %d", rec.Code)
	}
	hs.now = hs.now.Add(61 * time.Second)
	hs.login()
	// Session idle timeout
	hs.now = hs.now.Add(31 * time.Minute)
	if hs.do("GET", "/v1/admin/secrets", "", nil).Code != 401 {
		t.Fatal("expired session accepted")
	}
}

func TestValidation(t *testing.T) {
	hs := newHarness(t)
	if hs.do("POST", "/v1/sys/init", `{"username":"x","password":"short"}`, nil).Code != 422 {
		t.Fatal("weak init accepted")
	}
	hs.initAndLogin()
	bad := map[string]string{
		"/v1/admin/secrets/onlyone": `{"kind":"static","value":"x"}`,
		"/v1/admin/secrets/a/../b":  `{"kind":"static","value":"x"}`,
		"/v1/admin/secrets/a/b":     `{"kind":"magic","value":"x"}`,
		"/v1/admin/secrets/a/c":     `{"kind":"generated","length":4}`,
		"/v1/admin/secrets/a/d":     `{"kind":"static","value":"x","extra":1}`,
	}
	for path, body := range bad {
		code := hs.do("PUT", path, body, nil).Code
		// "a/../b" is cleaned by the router with a redirect; the handler never runs
		if code < 400 && !(strings.Contains(path, "..") && code == http.StatusTemporaryRedirect) {
			t.Errorf("%s %s: %d", path, body, code)
		}
	}
	if hs.do("POST", "/v1/admin/clients", `{"name":"x y","policies":["a"]}`, nil).Code != 422 {
		t.Fatal("bad client name accepted")
	}
	if hs.do("POST", "/v1/admin/clients", `{"name":"svc","policies":["../etc"]}`, nil).Code != 422 {
		t.Fatal("bad policy accepted")
	}
	rec := hs.do("GET", "/v1/sys/status", "", nil)
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("security headers missing")
	}
}

func TestMasterKeyRotation(t *testing.T) {
	hs := newHarness(t)
	old := hs.initAndLogin()
	next := decode(t, hs.do("POST", "/v1/admin/master-key/rotate", "", nil))["master_key"].(string)
	hs.do("POST", "/v1/sys/seal", "", nil)
	if hs.do("POST", "/v1/sys/unseal", `{"master_key":"`+old+`"}`, nil).Code != 400 {
		t.Fatal("old master key still unseals")
	}
	if hs.do("POST", "/v1/sys/unseal", `{"master_key":"`+next+`"}`, nil).Code != 200 {
		t.Fatal("new master key rejected")
	}
}
