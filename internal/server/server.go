// Package server is the secrets manager's HTTP API and admin UI.
//
// Admin: session cookie (after unseal), state changes need the CSRF header.
// Clients: bearer token, read-only on the paths their policy allows.
// Values never appear in logs, errors or list responses.
package server

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"secrets-manager/internal/audit"
	"secrets-manager/internal/crypto"
	"secrets-manager/internal/store"
)

const (
	maxBody       = 1 << 20
	csrfHeader    = "X-Requested-With"
	csrfValue     = "secrets-manager"
	sessionCookie = "sm_session"
	tokenPrefix   = "smt_"
)

// Config of the server.
type Config struct {
	DataDir      string
	CookieSecure bool
	GracePeriod  time.Duration // previous version stays readable this long after a change
	SessionIdle  time.Duration
	Logger       *slog.Logger
	UI           fs.FS // embedded admin UI (nil: no UI)
	Now          func() time.Time
}

type session struct {
	user    string
	expires time.Time
}

// Server holds the (un)sealed vault.
type Server struct {
	cfg      Config
	mu       sync.Mutex
	vault    *store.Vault
	audit    *audit.Log
	sessions map[string]session
	login    *limiter
	unseal   *limiter
}

// New prepares the server (sealed until unseal or init).
func New(cfg Config) (*Server, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.SessionIdle == 0 {
		cfg.SessionIdle = 30 * time.Minute
	}
	if cfg.GracePeriod == 0 {
		cfg.GracePeriod = 24 * time.Hour
	}
	log, err := audit.Open(filepath.Join(cfg.DataDir, "audit.log"))
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:      cfg,
		audit:    log,
		sessions: map[string]session{},
		login:    newLimiter(5, time.Minute),
		unseal:   newLimiter(10, time.Minute),
	}, nil
}

func (s *Server) statePath() string { return filepath.Join(s.cfg.DataDir, "state.json") }

// Unseal opens the vault with the master key (also used for dev auto-unseal).
func (s *Server) Unseal(master []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault != nil {
		return nil
	}
	v, err := store.Open(s.statePath(), master)
	if err != nil {
		return err
	}
	s.vault = v
	return nil
}

// Handler with all routes and security headers.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /v1/sys/status", s.status)
	mux.HandleFunc("POST /v1/sys/init", s.csrf(s.initVault))
	mux.HandleFunc("POST /v1/sys/unseal", s.csrf(s.unsealVault))
	mux.HandleFunc("POST /v1/sys/seal", s.csrf(s.admin(s.seal)))
	mux.HandleFunc("POST /v1/admin/login", s.csrf(s.adminLogin))
	mux.HandleFunc("POST /v1/admin/logout", s.csrf(s.adminLogout))
	mux.HandleFunc("GET /v1/admin/session", s.admin(s.sessionInfo))
	mux.HandleFunc("GET /v1/admin/secrets", s.admin(s.listSecrets))
	mux.HandleFunc("PUT /v1/admin/secrets/{path...}", s.csrf(s.admin(s.putSecret)))
	mux.HandleFunc("DELETE /v1/admin/secrets/{path...}", s.csrf(s.admin(s.deleteSecret)))
	mux.HandleFunc("POST /v1/admin/reveal/{path...}", s.csrf(s.admin(s.revealSecret)))
	mux.HandleFunc("POST /v1/admin/rotate/{path...}", s.csrf(s.admin(s.rotateSecret)))
	mux.HandleFunc("GET /v1/admin/clients", s.admin(s.listClients))
	mux.HandleFunc("POST /v1/admin/clients", s.csrf(s.admin(s.createClient)))
	mux.HandleFunc("DELETE /v1/admin/clients/{id}", s.csrf(s.admin(s.revokeClient)))
	mux.HandleFunc("POST /v1/admin/master-key/rotate", s.csrf(s.admin(s.rotateMasterKey)))
	mux.HandleFunc("GET /v1/admin/audit", s.admin(s.auditTail))
	mux.HandleFunc("GET /v1/admin/audit/verify", s.admin(s.auditVerify))
	mux.HandleFunc("GET /v1/secrets/{path...}", s.clientRead)
	if s.cfg.UI != nil {
		mux.Handle("GET /", http.FileServerFS(s.cfg.UI))
	}
	return headers(http.MaxBytesHandler(mux, maxBody))
}

// ---------------------------------------------------------------- helpers

func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// csrf: state-changing requests must carry the custom header (browsers cannot
// add it cross-site without CORS, which the server never allows).
func (s *Server) csrf(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(csrfHeader) != csrfValue {
			fail(w, http.StatusForbidden, "missing request header")
			return
		}
		next(w, r)
	}
}

type adminHandler func(w http.ResponseWriter, r *http.Request, user string)

// admin: unsealed vault + valid session (sliding idle timeout).
func (s *Server) admin(next adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		s.mu.Lock()
		sealed := s.vault == nil
		var user string
		if err == nil && !sealed {
			if sess, ok := s.sessions[cookie.Value]; ok && s.cfg.Now().Before(sess.expires) {
				user = sess.user
				s.sessions[cookie.Value] = session{user: user, expires: s.cfg.Now().Add(s.cfg.SessionIdle)}
			} else {
				delete(s.sessions, cookie.Value)
			}
		}
		s.mu.Unlock()
		if sealed {
			fail(w, http.StatusServiceUnavailable, "sealed")
			return
		}
		if user == "" {
			fail(w, http.StatusUnauthorized, "not signed in")
			return
		}
		next(w, r, user)
	}
}

func (s *Server) record(actor, action, path string, version int, ok bool, detail string) {
	if err := s.audit.Write(actor, action, path, version, ok, detail); err != nil {
		s.cfg.Logger.Error("audit write failed", "action", action)
	}
}

// ---------------------------------------------------------------- system

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"initialized": store.Exists(s.statePath()), "sealed": s.vault == nil})
}

func (s *Server) initVault(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &body); err != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	if !usernamePattern.MatchString(body.Username) {
		fail(w, 422, "username: 3-40 characters a-z 0-9 . _ -")
		return
	}
	if len(body.Password) < 14 || len(body.Password) > 200 {
		fail(w, 422, "password: 14-200 characters")
		return
	}
	salt, hash, err := crypto.PasswordHash(body.Password)
	if err != nil {
		fail(w, 500, "internal error")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if store.Exists(s.statePath()) {
		fail(w, 409, "already initialized")
		return
	}
	v, master, err := store.Create(s.statePath(), store.Admin{
		Username: body.Username, Salt: salt, Hash: hash, Iterations: crypto.PasswordIterations, CreatedAt: s.cfg.Now(),
	})
	if err != nil {
		fail(w, 500, "initialization failed")
		return
	}
	s.vault = v
	s.record("admin:"+body.Username, "vault.init", "", 0, true, "")
	// The only moment the master key leaves the server
	writeJSON(w, 201, map[string]string{"master_key": crypto.EncodeKey(master)})
}

func (s *Server) unsealVault(w http.ResponseWriter, r *http.Request) {
	if !s.unseal.allow(clientIP(r), s.cfg.Now()) {
		w.Header().Set("Retry-After", "60")
		fail(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	var body struct {
		MasterKey string `json:"master_key"`
	}
	if err := readJSON(r, &body); err != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	key, err := crypto.DecodeKey(body.MasterKey)
	if err == nil {
		err = s.Unseal(key)
	}
	if err != nil {
		s.unseal.failed(clientIP(r), s.cfg.Now())
		s.record("anonymous", "vault.unseal", "", 0, false, "")
		fail(w, 400, "unseal failed")
		return
	}
	s.record("anonymous", "vault.unseal", "", 0, true, "")
	writeJSON(w, 200, map[string]bool{"sealed": false})
}

func (s *Server) seal(w http.ResponseWriter, _ *http.Request, user string) {
	s.mu.Lock()
	if s.vault != nil {
		s.vault.Close()
		s.vault = nil
	}
	s.sessions = map[string]session{}
	s.mu.Unlock()
	s.record("admin:"+user, "vault.seal", "", 0, true, "")
	writeJSON(w, 200, map[string]bool{"sealed": true})
}

// ---------------------------------------------------------------- admin session

func (s *Server) adminLogin(w http.ResponseWriter, r *http.Request) {
	if !s.login.allow(clientIP(r), s.cfg.Now()) {
		w.Header().Set("Retry-After", "60")
		fail(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &body); err != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	s.mu.Lock()
	if s.vault == nil {
		s.mu.Unlock()
		fail(w, http.StatusServiceUnavailable, "sealed")
		return
	}
	admin := s.vault.State.Admin
	s.mu.Unlock()
	// Always run the hash, also for unknown users (same timing, same message)
	ok := crypto.PasswordVerify(body.Password, admin.Salt, admin.Hash, admin.Iterations) && body.Username == admin.Username
	if !ok {
		s.login.failed(clientIP(r), s.cfg.Now())
		s.record("anonymous", "admin.login", "", 0, false, "")
		fail(w, 401, "invalid username or password")
		return
	}
	id, err := crypto.RandomString("base64url", 32)
	if err != nil {
		fail(w, 500, "internal error")
		return
	}
	s.mu.Lock()
	s.sessions[id] = session{user: admin.Username, expires: s.cfg.Now().Add(s.cfg.SessionIdle)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
	s.record("admin:"+admin.Username, "admin.login", "", 0, true, "")
	writeJSON(w, 200, map[string]string{"user": admin.Username})
}

func (s *Server) adminLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) sessionInfo(w http.ResponseWriter, _ *http.Request, user string) {
	writeJSON(w, 200, map[string]string{"user": user})
}

// ---------------------------------------------------------------- secrets (admin)

type secretView struct {
	Path           string    `json:"path"`
	Kind           string    `json:"kind"`
	Alphabet       string    `json:"alphabet,omitempty"`
	Length         int       `json:"length,omitempty"`
	Note           string    `json:"note,omitempty"`
	CurrentVersion int       `json:"current_version"`
	Versions       int       `json:"versions"`
	UpdatedAt      time.Time `json:"updated_at"`
	UpdatedBy      string    `json:"updated_by"`
	CreatedAt      time.Time `json:"created_at"`
	Readers        []string  `json:"readers"`
}

func (s *Server) view(path string, sec *store.Secret) secretView {
	cur := sec.Current()
	readers := []string{}
	for _, c := range s.vault.State.Clients {
		if c.Allows(path) {
			readers = append(readers, c.Name)
		}
	}
	return secretView{
		Path: path, Kind: sec.Kind, Alphabet: sec.Alphabet, Length: sec.Length, Note: sec.Note,
		CurrentVersion: cur.Number, Versions: len(sec.Versions), UpdatedAt: cur.CreatedAt, UpdatedBy: cur.CreatedBy,
		CreatedAt: sec.CreatedAt, Readers: readers,
	}
}

func (s *Server) listSecrets(w http.ResponseWriter, _ *http.Request, _ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []secretView{}
	for _, p := range s.vault.State.SecretPaths() {
		out = append(out, s.view(p, s.vault.State.Secrets[p]))
	}
	writeJSON(w, 200, out)
}

func (s *Server) putSecret(w http.ResponseWriter, r *http.Request, user string) {
	path := r.PathValue("path")
	if !store.ValidPath(path) {
		fail(w, 422, "invalid path")
		return
	}
	var body struct {
		Kind     string `json:"kind"`
		Value    string `json:"value"`
		Alphabet string `json:"alphabet"`
		Length   int    `json:"length"`
		Note     string `json:"note"`
	}
	if err := readJSON(r, &body); err != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	if len(body.Note) > 300 {
		fail(w, 422, "note too long")
		return
	}
	var value string
	switch body.Kind {
	case "static":
		if body.Value == "" || len(body.Value) > 16<<10 {
			fail(w, 422, "value: 1 to 16384 characters")
			return
		}
		value = body.Value
	case "generated":
		if body.Alphabet == "" {
			body.Alphabet = "alnum"
		}
		if body.Length == 0 {
			body.Length = 40
		}
		v, err := crypto.RandomString(body.Alphabet, body.Length)
		if err != nil {
			fail(w, 422, err.Error())
			return
		}
		value = v
	default:
		fail(w, 422, "kind must be static or generated")
		return
	}
	actor := "admin:" + user
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	sec, exists := s.vault.State.Secrets[path]
	if exists && sec.Kind != body.Kind {
		fail(w, 409, "kind cannot change; delete and recreate")
		return
	}
	if exists && body.Kind == "generated" {
		fail(w, 409, "exists; use rotate for a new value")
		return
	}
	if !exists {
		sec = &store.Secret{Kind: body.Kind, CreatedAt: now}
		if body.Kind == "generated" {
			sec.Alphabet, sec.Length = body.Alphabet, body.Length
		}
		s.vault.State.Secrets[path] = sec
	}
	if body.Note != "" {
		sec.Note = body.Note
	}
	version := sec.PutVersion(value, actor, now)
	if err := s.vault.Save(); err != nil {
		fail(w, 500, "save failed")
		return
	}
	s.record(actor, "secret.set", path, version.Number, true, body.Kind)
	writeJSON(w, 200, s.view(path, sec))
}

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request, user string) {
	path := r.PathValue("path")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.vault.State.Secrets[path]; !ok {
		fail(w, 404, "not found")
		return
	}
	delete(s.vault.State.Secrets, path)
	if err := s.vault.Save(); err != nil {
		fail(w, 500, "save failed")
		return
	}
	s.record("admin:"+user, "secret.delete", path, 0, true, "")
	w.WriteHeader(204)
}

func (s *Server) revealSecret(w http.ResponseWriter, r *http.Request, user string) {
	path := r.PathValue("path")
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.vault.State.Secrets[path]
	if !ok {
		fail(w, 404, "not found")
		return
	}
	cur := sec.Current()
	s.record("admin:"+user, "secret.reveal", path, cur.Number, true, "")
	writeJSON(w, 200, map[string]any{"path": path, "version": cur.Number, "value": cur.Value})
}

func (s *Server) rotateSecret(w http.ResponseWriter, r *http.Request, user string) {
	path := r.PathValue("path")
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.vault.State.Secrets[path]
	if !ok {
		fail(w, 404, "not found")
		return
	}
	if sec.Kind != "generated" {
		fail(w, 409, "only generated secrets rotate; set a new value instead")
		return
	}
	value, err := crypto.RandomString(sec.Alphabet, sec.Length)
	if err != nil {
		fail(w, 500, "internal error")
		return
	}
	version := sec.PutVersion(value, "admin:"+user, s.cfg.Now())
	if err := s.vault.Save(); err != nil {
		fail(w, 500, "save failed")
		return
	}
	s.record("admin:"+user, "secret.rotate", path, version.Number, true, "")
	writeJSON(w, 200, s.view(path, sec))
}

// ---------------------------------------------------------------- clients (admin)

type clientView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Policies   []string   `json:"policies"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

func viewClient(c *store.Client) clientView {
	return clientView{ID: c.ID, Name: c.Name, Policies: c.Policies, CreatedAt: c.CreatedAt, LastUsedAt: c.LastUsedAt, RevokedAt: c.RevokedAt}
}

var usernamePattern = regexp.MustCompile(`^[a-z0-9._-]{3,40}$`)
var clientName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,40}$`)
var policyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}(/[a-z0-9][a-z0-9_-]{0,62}){0,4}$`)

func (s *Server) listClients(w http.ResponseWriter, _ *http.Request, _ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []clientView{}
	for _, c := range s.vault.State.Clients {
		out = append(out, viewClient(c))
	}
	writeJSON(w, 200, out)
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request, user string) {
	var body struct {
		Name     string   `json:"name"`
		Policies []string `json:"policies"`
	}
	if err := readJSON(r, &body); err != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	if !clientName.MatchString(body.Name) {
		fail(w, 422, "name: 2-41 characters a-z 0-9 _ -")
		return
	}
	if len(body.Policies) == 0 || len(body.Policies) > 20 {
		fail(w, 422, "1 to 20 policies")
		return
	}
	for _, p := range body.Policies {
		if !policyPattern.MatchString(p) {
			fail(w, 422, "invalid policy path")
			return
		}
	}
	id, err1 := crypto.RandomString("hex", 16)
	random, err2 := crypto.RandomString("base64url", 32)
	if errors.Join(err1, err2) != nil {
		fail(w, 500, "internal error")
		return
	}
	token := tokenPrefix + random
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.vault.State.Clients {
		if c.Name == body.Name && c.RevokedAt == nil {
			fail(w, 409, "a client with this name exists")
			return
		}
	}
	c := &store.Client{
		ID: id, Name: body.Name, TokenMAC: crypto.MAC(s.vault.State.ServerKey, token),
		Policies: body.Policies, CreatedAt: s.cfg.Now(),
	}
	s.vault.State.Clients[id] = c
	if err := s.vault.Save(); err != nil {
		fail(w, 500, "save failed")
		return
	}
	s.record("admin:"+user, "client.create", strings.Join(body.Policies, ","), 0, true, body.Name)
	writeJSON(w, 201, map[string]any{"client": viewClient(c), "token": token})
}

func (s *Server) revokeClient(w http.ResponseWriter, r *http.Request, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.vault.State.Clients[r.PathValue("id")]
	if !ok {
		fail(w, 404, "not found")
		return
	}
	if c.RevokedAt == nil {
		now := s.cfg.Now()
		c.RevokedAt = &now
		if err := s.vault.Save(); err != nil {
			fail(w, 500, "save failed")
			return
		}
		s.record("admin:"+user, "client.revoke", "", 0, true, c.Name)
	}
	w.WriteHeader(204)
}

func (s *Server) rotateMasterKey(w http.ResponseWriter, _ *http.Request, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := s.vault.ChangeMasterKey()
	if err != nil {
		fail(w, 500, "rotation failed")
		return
	}
	s.record("admin:"+user, "vault.master_key_rotate", "", 0, true, "")
	writeJSON(w, 200, map[string]string{"master_key": crypto.EncodeKey(next)})
}

// ---------------------------------------------------------------- audit (admin)

func (s *Server) auditTail(w http.ResponseWriter, _ *http.Request, _ string) {
	entries, err := s.audit.Tail(200)
	if err != nil {
		fail(w, 500, "audit log unreadable")
		return
	}
	if entries == nil {
		entries = []audit.Entry{}
	}
	writeJSON(w, 200, entries)
}

func (s *Server) auditVerify(w http.ResponseWriter, _ *http.Request, _ string) {
	n, err := s.audit.Verify()
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "entries": n, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "entries": n, "head": s.audit.Head()})
}

// ---------------------------------------------------------------- clients (read)

func (s *Server) clientRead(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !strings.HasPrefix(token, tokenPrefix) {
		fail(w, 401, "unauthorized")
		return
	}
	path := r.PathValue("path")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		fail(w, http.StatusServiceUnavailable, "sealed")
		return
	}
	mac := crypto.MAC(s.vault.State.ServerKey, token)
	var client *store.Client
	for _, c := range s.vault.State.Clients {
		if crypto.MACEqual(c.TokenMAC, mac) {
			client = c
		}
	}
	if client == nil || client.RevokedAt != nil {
		s.record("anonymous", "secret.read", path, 0, false, "unknown token")
		fail(w, 401, "unauthorized")
		return
	}
	actor := "client:" + client.Name
	sec, exists := s.vault.State.Secrets[path]
	// Same answer for "not allowed" and "does not exist": no probing of paths
	if !client.Allows(path) || !exists {
		s.record(actor, "secret.read", path, 0, false, "denied")
		fail(w, 403, "forbidden")
		return
	}
	version := sec.Current()
	if r.URL.Query().Get("version") == "previous" {
		prev, ok := sec.Previous()
		if !ok || s.cfg.Now().Sub(version.CreatedAt) > s.cfg.GracePeriod {
			fail(w, 404, "no previous version in grace period")
			return
		}
		version = prev
	}
	now := s.cfg.Now()
	client.LastUsedAt = &now
	if err := s.vault.Save(); err != nil {
		s.cfg.Logger.Warn("could not record last use")
	}
	s.record(actor, "secret.read", path, version.Number, true, "")
	writeJSON(w, 200, map[string]any{"path": path, "version": version.Number, "value": version.Value})
}

// ---------------------------------------------------------------- rate limiter

type limiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
}

func newLimiter(limit int, window time.Duration) *limiter {
	return &limiter{limit: limit, window: window, hits: map[string][]time.Time{}}
}

// allow reports whether another attempt is permitted (does not count it).
func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(key, now)) < l.limit
}

// failed counts one failed attempt.
func (l *limiter) failed(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits[key] = append(l.recent(key, now), now)
}

func (l *limiter) recent(key string, now time.Time) []time.Time {
	recent := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if now.Sub(t) < l.window {
			recent = append(recent, t)
		}
	}
	l.hits[key] = recent
	return recent
}
