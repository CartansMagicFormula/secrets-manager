package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newCSR(t *testing.T, tmpl *x509.CertificateRequest) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func jsonString(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

func TestAccessTokens(t *testing.T) {
	hs := newHarness(t)
	hs.initAndLogin()
	hs.do("PUT", "/v1/admin/secrets/svc/key", `{"kind":"static","value":"v1"}`, nil)
	start := decode(t, hs.do("POST", "/v1/admin/clients", `{"name":"svc","policies":["svc"]}`, nil))["token"].(string)
	auth := func(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

	// Instance name is validated; a wrong start token counts toward the limit
	if hs.do("POST", "/v1/auth/login", `{"instance":"bad name!"}`, auth(start)).Code != 422 {
		t.Fatal("invalid instance accepted")
	}
	access := hs.clientLogin(start, "svc-1")
	if !strings.HasPrefix(access, accessPrefix) {
		t.Fatal("access token prefix")
	}
	// An access token cannot be used to log in (no self-renewal past the maximum)
	if hs.do("POST", "/v1/auth/login", `{"instance":"svc-1"}`, auth(access)).Code != 401 {
		t.Fatal("access token accepted as start token")
	}

	// Renewal extends by one TTL, never past the maximum lifetime
	hs.now = hs.now.Add(50 * time.Minute)
	if hs.do("POST", "/v1/auth/renew", "", auth(access)).Code != 200 {
		t.Fatal("renew")
	}
	hs.now = hs.now.Add(50 * time.Minute) // 100 min after login, 50 after renewal
	if hs.do("GET", "/v1/secrets/svc/key", "", auth(access)).Code != 200 {
		t.Fatal("renewed token rejected")
	}
	for i := 0; i < 30; i++ {
		hs.now = hs.now.Add(50 * time.Minute)
		hs.do("POST", "/v1/auth/renew", "", auth(access))
	}
	if hs.do("GET", "/v1/secrets/svc/key", "", auth(access)).Code != 401 {
		t.Fatal("access token outlived its maximum lifetime")
	}

	// Sessions are listed per instance and can be ended by the admin
	hs.login()
	access = hs.clientLogin(start, "svc-2")
	var sessions []map[string]any
	_ = json.Unmarshal(hs.do("GET", "/v1/admin/sessions", "", nil).Body.Bytes(), &sessions)
	if len(sessions) != 1 || sessions[0]["instance"] != "svc-2" {
		t.Fatalf("sessions: %v", sessions)
	}
	if strings.Contains(hs.do("GET", "/v1/admin/sessions", "", nil).Body.String(), access) {
		t.Fatal("session list leaks the token")
	}
	if hs.do("DELETE", "/v1/admin/sessions/"+sessions[0]["id"].(string), "", nil).Code != 204 {
		t.Fatal("end session")
	}
	if hs.do("GET", "/v1/secrets/svc/key", "", auth(access)).Code != 401 {
		t.Fatal("ended session still valid")
	}

	// Logout ends the session; the session cap drops the oldest
	access = hs.clientLogin(start, "svc-3")
	if hs.do("POST", "/v1/auth/logout", "", auth(access)).Code != 204 || hs.do("GET", "/v1/secrets/svc/key", "", auth(access)).Code != 401 {
		t.Fatal("logout")
	}
	first := hs.clientLogin(start, "svc-first")
	for i := 0; i < maxSessions; i++ {
		hs.now = hs.now.Add(time.Second)
		hs.clientLogin(start, "svc-n")
	}
	if hs.do("GET", "/v1/secrets/svc/key", "", auth(first)).Code != 401 {
		t.Fatal("session cap not enforced")
	}

	// Brute force on login: 10 failures per minute per address
	for i := 0; i < 10; i++ {
		hs.do("POST", "/v1/auth/login", `{"instance":"x"}`, auth("smt_wrong"))
	}
	if hs.do("POST", "/v1/auth/login", `{"instance":"x"}`, auth(start)).Code != 429 {
		t.Fatal("login not rate limited")
	}
}

func TestAdminOnlyListener(t *testing.T) {
	hs := newHarness(t)
	hs.h = AdminOnly(hs.srv.Handler())
	hs.initAndLogin()
	start := decode(t, hs.do("POST", "/v1/admin/clients", `{"name":"svc","policies":["svc"]}`, nil))["token"].(string)
	for _, path := range []string{"/v1/auth/login", "/v1/auth/enroll", "/v1/secrets/svc/key", "/v1/pki/issue"} {
		if hs.do("POST", path, `{"instance":"a"}`, map[string]string{"Authorization": "Bearer " + start}).Code != 404 {
			t.Errorf("%s reachable on the admin listener", path)
		}
	}
	if hs.do("GET", "/v1/admin/clients", "", nil).Code != 200 {
		t.Fatal("admin API not reachable on the admin listener")
	}
}

func TestCertificates(t *testing.T) {
	hs := newHarness(t)
	hs.srv.cfg.CAExportDir = hs.dir
	hs.initAndLogin()
	caFile, err := os.ReadFile(filepath.Join(hs.dir, caFileName))
	if err != nil || !strings.Contains(string(caFile), "BEGIN CERTIFICATE") {
		t.Fatal("CA certificate not exported")
	}
	if hs.do("GET", "/v1/pki/ca", "", nil).Body.String() != string(caFile) {
		t.Fatal("CA endpoint differs from the exported file")
	}
	if hs.do("POST", "/v1/admin/clients", `{"name":"pg","pki_names":["bad_name!"]}`, nil).Code != 422 {
		t.Fatal("invalid certificate name accepted")
	}
	start := decode(t, hs.do("POST", "/v1/admin/clients", `{"name":"pg","pki_names":["postgres","lumen-postgres-1","127.0.0.1"]}`, nil))["token"].(string)
	access := hs.clientLogin(start, "pg-1")
	auth := map[string]string{"Authorization": "Bearer " + access}

	ok := newCSR(t, &x509.CertificateRequest{DNSNames: []string{"postgres", "lumen-postgres-1"}})
	rec := hs.do("POST", "/v1/pki/issue", `{"usage":"server","ttl":"720h","csr":`+jsonString(ok)+`}`, auth)
	if rec.Code != 200 {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body)
	}
	out := decode(t, rec)
	block, _ := pem.Decode([]byte(out["certificate"].(string)))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caFile)
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "lumen-postgres-1", Roots: pool, CurrentTime: hs.now}); err != nil {
		t.Fatalf("certificate does not verify against the exported CA: %v", err)
	}

	evil := newCSR(t, &x509.CertificateRequest{DNSNames: []string{"postgres", "keycloak"}})
	if hs.do("POST", "/v1/pki/issue", `{"usage":"server","csr":`+jsonString(evil)+`}`, auth).Code != 422 {
		t.Fatal("certificate for a foreign name issued")
	}
	client := newCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "postgres"}})
	if hs.do("POST", "/v1/pki/issue", `{"usage":"client","csr":`+jsonString(client)+`}`, auth).Code != 200 {
		t.Fatal("client certificate for an allowed name refused")
	}
	if hs.do("POST", "/v1/pki/issue", `{"usage":"server","csr":`+jsonString(ok)+`}`, nil).Code != 401 {
		t.Fatal("issue without token")
	}

	// Inventory lists issued certificates (no keys), the audit has the serials
	inv := hs.do("GET", "/v1/admin/certificates", "", nil).Body.String()
	if !strings.Contains(inv, out["serial"].(string)) || strings.Contains(inv, "PRIVATE KEY") {
		t.Fatalf("inventory: %s", inv)
	}
	raw, _ := os.ReadFile(filepath.Join(hs.dir, "state.json"))
	if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "BEGIN CERTIFICATE") {
		t.Fatal("CA material in clear on disk")
	}

	// TLS listener: CA certificate while unsealed, self-signed while sealed
	cfg, err := hs.srv.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	unsealed, err := cfg.GetCertificate(nil)
	if err != nil || unsealed.Leaf.Issuer.CommonName != "Fleet internal CA" {
		t.Fatal("vault does not serve its CA certificate")
	}
	hs.do("POST", "/v1/sys/seal", "", nil)
	sealed, _ := cfg.GetCertificate(nil)
	if sealed.Leaf.Issuer.CommonName == "Fleet internal CA" {
		t.Fatal("CA certificate served while sealed")
	}
	if hs.do("GET", "/v1/pki/ca", "", nil).Code != 503 {
		t.Fatal("CA endpoint answers while sealed")
	}
}
