package server

// Client authentication (start token → short-lived access token per container),
// the internal PKI (certificates from CSRs) and the vault's own TLS listener.

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"secrets-manager/internal/crypto"
	"secrets-manager/internal/pki"
	"secrets-manager/internal/store"
)

const (
	accessPrefix      = "sma_"
	maxSessions       = 20 // per client; the oldest is dropped beyond that
	caFileName        = "fleet-ca.crt"
	vaultCertLifetime = 7 * 24 * time.Hour
)

var instancePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
var pkiNamePattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// access is one container instance's session (memory only: after a restart
// of the vault every client logs in again).
type access struct {
	ID       string    `json:"id"`
	ClientID string    `json:"client_id"`
	Client   string    `json:"client"`
	Instance string    `json:"instance"`
	IssuedAt time.Time `json:"issued_at"`
	Expires  time.Time `json:"expires_at"`
	MaxUntil time.Time `json:"max_until"` // renewals stop here; then log in again
}

func bearer(r *http.Request) string {
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return token
}

// accessFor resolves an access token (caller holds s.mu, vault unsealed).
func (s *Server) accessFor(token string) (*access, *store.Client) {
	if !strings.HasPrefix(token, accessPrefix) {
		return nil, nil
	}
	a := s.access[string(crypto.MAC(s.vault.State.ServerKey, token))]
	if a == nil || !s.cfg.Now().Before(a.Expires) {
		return nil, nil
	}
	c := s.vault.State.Clients[a.ClientID]
	if c == nil || c.RevokedAt != nil {
		return nil, nil
	}
	return a, c
}

// clientAuth wraps client endpoints: unsealed vault + valid access token.
func (s *Server) clientAuth(next func(w http.ResponseWriter, r *http.Request, a *access, c *store.Client)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.vault == nil {
			fail(w, http.StatusServiceUnavailable, "sealed")
			return
		}
		a, c := s.accessFor(bearer(r))
		if a == nil {
			s.record("anonymous", "client.auth", r.URL.Path, 0, false, "invalid or expired access token")
			fail(w, 401, "unauthorized")
			return
		}
		next(w, r, a, c)
	}
}

func (s *Server) dropExpired(now time.Time) {
	for k, a := range s.access {
		if !now.Before(a.Expires) {
			delete(s.access, k)
		}
	}
}

// clientByStartToken finds the client of a start token: its current token, or
// its previous one during the grace period after a rotation (caller holds s.mu).
func (s *Server) clientByStartToken(token string) *store.Client {
	if !strings.HasPrefix(token, tokenPrefix) {
		return nil
	}
	mac := crypto.MAC(s.vault.State.ServerKey, token)
	now := s.cfg.Now()
	var found *store.Client
	for _, c := range s.vault.State.Clients {
		current := crypto.MACEqual(c.TokenMAC, mac)
		previous := c.PrevTokenMAC != nil && c.PrevUntil != nil && now.Before(*c.PrevUntil) && crypto.MACEqual(c.PrevTokenMAC, mac)
		if current || previous {
			found = c
		}
	}
	return found
}

// login exchanges the client's start token (long-lived, only good for this
// endpoint) for an access token bound to one container instance.
func (s *Server) clientLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.authLimit.allow(ip, s.cfg.Now()) {
		w.Header().Set("Retry-After", "60")
		fail(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	var body struct {
		Instance string `json:"instance"`
	}
	if err := readJSON(r, &body); err != nil || !instancePattern.MatchString(body.Instance) {
		fail(w, 422, "instance: 1-63 characters A-Z a-z 0-9 . _ -")
		return
	}
	token := bearer(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		fail(w, http.StatusServiceUnavailable, "sealed")
		return
	}
	client := s.clientByStartToken(token)
	if client == nil || client.RevokedAt != nil {
		s.authLimit.failed(ip, s.cfg.Now())
		s.record("anonymous", "client.login", "", 0, false, "unknown start token")
		fail(w, 401, "unauthorized")
		return
	}
	now := s.cfg.Now()
	s.dropExpired(now)
	var mine []*access
	for _, a := range s.access {
		if a.ClientID == client.ID {
			mine = append(mine, a)
		}
	}
	if len(mine) >= maxSessions {
		sort.Slice(mine, func(i, j int) bool { return mine[i].IssuedAt.Before(mine[j].IssuedAt) })
		for k, a := range s.access {
			if a == mine[0] {
				delete(s.access, k)
			}
		}
	}
	id, err1 := crypto.RandomString("hex", 16)
	random, err2 := crypto.RandomString("base64url", 32)
	if errors.Join(err1, err2) != nil {
		fail(w, 500, "internal error")
		return
	}
	accessToken := accessPrefix + random
	a := &access{
		ID: id, ClientID: client.ID, Client: client.Name, Instance: body.Instance,
		IssuedAt: now, Expires: now.Add(s.cfg.AccessTTL), MaxUntil: now.Add(s.cfg.AccessMax),
	}
	s.access[string(crypto.MAC(s.vault.State.ServerKey, accessToken))] = a
	client.LastUsedAt = &now
	if err := s.vault.Save(); err != nil {
		s.cfg.Logger.Warn("could not record last use")
	}
	s.record("client:"+client.Name, "client.login", "", 0, true, "instance "+body.Instance)
	writeJSON(w, 200, map[string]any{"access_token": accessToken, "expires_at": a.Expires, "max_until": a.MaxUntil})
}

func (s *Server) renew(w http.ResponseWriter, _ *http.Request, a *access, c *store.Client) {
	now := s.cfg.Now()
	if !now.Before(a.MaxUntil) {
		fail(w, 401, "maximum lifetime reached; log in again")
		return
	}
	a.Expires = now.Add(s.cfg.AccessTTL)
	if a.Expires.After(a.MaxUntil) {
		a.Expires = a.MaxUntil
	}
	s.record("client:"+c.Name, "client.renew", "", 0, true, "instance "+a.Instance)
	writeJSON(w, 200, map[string]any{"expires_at": a.Expires, "max_until": a.MaxUntil})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, a *access, c *store.Client) {
	delete(s.access, string(crypto.MAC(s.vault.State.ServerKey, bearer(r))))
	s.record("client:"+c.Name, "client.logout", "", 0, true, "instance "+a.Instance)
	w.WriteHeader(204)
}

// ---------------------------------------------------------------- PKI

func (s *Server) exportCA() {
	if s.cfg.CAExportDir == "" || s.ca == nil {
		return
	}
	path := filepath.Join(s.cfg.CAExportDir, caFileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, s.ca.CertPEM, 0o644); err != nil || os.Rename(tmp, path) != nil {
		s.cfg.Logger.Error("could not export the CA certificate", "dir", s.cfg.CAExportDir)
	}
}

// ensureCA creates the CA on first unseal / init and loads it (caller holds s.mu).
func (s *Server) ensureCA() error {
	st := s.vault.State
	if st.CA == nil {
		certPEM, keyDER, err := pki.NewCA("Fleet internal CA", s.cfg.Now())
		if err != nil {
			return err
		}
		st.CA = &store.CA{CertPEM: certPEM, KeyDER: keyDER, CreatedAt: s.cfg.Now()}
		if err := s.vault.Save(); err != nil {
			st.CA = nil
			return err
		}
		s.record("system", "pki.ca_create", "", 0, true, "")
	}
	ca, err := pki.LoadCA(st.CA.CertPEM, st.CA.KeyDER)
	if err != nil {
		return err
	}
	s.ca, s.vaultCert = ca, nil
	s.exportCA()
	return nil
}

func (s *Server) caCert(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ca == nil {
		fail(w, http.StatusServiceUnavailable, "sealed")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(s.ca.CertPEM)
}

func (s *Server) issueCertificate(w http.ResponseWriter, r *http.Request, a *access, c *store.Client) {
	var body struct {
		CSR   string `json:"csr"`
		Usage string `json:"usage"`
		TTL   string `json:"ttl"`
	}
	if err := readJSON(r, &body); err != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	var ttl time.Duration
	if body.TTL != "" {
		d, err := time.ParseDuration(body.TTL)
		if err != nil {
			fail(w, 422, "ttl: Go duration, e.g. 720h")
			return
		}
		ttl = d
	}
	actor := "client:" + c.Name
	issued, err := s.ca.Issue(pki.Request{CSRPEM: []byte(body.CSR), Usage: body.Usage, TTL: ttl, Allowed: c.PKINames}, s.cfg.Now())
	if err != nil {
		s.record(actor, "pki.issue", "", 0, false, err.Error())
		fail(w, 422, err.Error())
		return
	}
	s.vault.State.AddCertificate(store.Certificate{
		Serial: issued.Serial, Client: c.Name, Usage: body.Usage, Names: issued.Names,
		IssuedAt: s.cfg.Now(), NotAfter: issued.NotAfter,
	})
	if err := s.vault.Save(); err != nil {
		s.cfg.Logger.Warn("could not record the certificate")
	}
	s.record(actor, "pki.issue", "", 0, true, body.Usage+" "+strings.Join(issued.Names, ",")+" serial "+issued.Serial+" instance "+a.Instance)
	writeJSON(w, 200, map[string]any{
		"certificate": string(issued.CertPEM), "ca": string(s.ca.CertPEM),
		"serial": issued.Serial, "not_after": issued.NotAfter,
	})
}

// TLSConfig for the vault's listener: while unsealed a certificate from its
// own CA (key in memory only, renewed after half its lifetime); while sealed a
// throwaway self-signed one that verifying clients reject.
func (s *Server) TLSConfig() (*tls.Config, error) {
	sealed, err := pki.SelfSigned(s.cfg.ServerNames, s.cfg.Now())
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.ca == nil {
				return sealed, nil
			}
			now := s.cfg.Now()
			if s.vaultCert == nil || now.After(s.vaultCert.Leaf.NotAfter.Add(-vaultCertLifetime/2)) {
				cert, err := s.ca.ServerCertificate(s.cfg.ServerNames, vaultCertLifetime, now)
				if err != nil {
					s.cfg.Logger.Error("vault certificate renewal failed")
					return sealed, nil
				}
				s.vaultCert = cert
			}
			return s.vaultCert, nil
		},
	}, nil
}

// AdminOnly serves everything except the client endpoints: for the optional
// plain-HTTP admin listener (dev, bound to localhost). Clients only ever talk TLS.
func AdminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/v1/auth/") || strings.HasPrefix(p, "/v1/secrets/") || strings.HasPrefix(p, "/v1/pki/issue") { // incl. /v1/auth/enroll
			fail(w, http.StatusNotFound, "clients use the TLS listener")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------- admin views

func (s *Server) listSessions(w http.ResponseWriter, _ *http.Request, _ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropExpired(s.cfg.Now())
	out := []*access{}
	for _, a := range s.access {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.After(out[j].IssuedAt) })
	writeJSON(w, 200, out)
}

func (s *Server) endSession(w http.ResponseWriter, r *http.Request, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, a := range s.access {
		if a.ID == r.PathValue("id") {
			delete(s.access, k)
			s.record("admin:"+user, "client.session_end", "", 0, true, a.Client+" instance "+a.Instance)
			w.WriteHeader(204)
			return
		}
	}
	fail(w, 404, "not found")
}

func (s *Server) listCertificates(w http.ResponseWriter, _ *http.Request, _ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]store.Certificate{}, s.vault.State.Certificates...)
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.After(out[j].IssuedAt) })
	ca := ""
	if s.ca != nil {
		ca = string(s.ca.CertPEM)
	}
	writeJSON(w, 200, map[string]any{"ca": ca, "certificates": out})
}

// dropClientSessions ends every session of a revoked client (caller holds s.mu).
func (s *Server) dropClientSessions(id string) {
	for k, a := range s.access {
		if a.ClientID == id {
			delete(s.access, k)
		}
	}
}

func validPKINames(names []string) bool {
	if len(names) > 20 {
		return false
	}
	for _, n := range names {
		if len(n) > 253 || !pkiNamePattern.MatchString(n) && net.ParseIP(n) == nil {
			return false
		}
	}
	return true
}
