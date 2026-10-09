package server

// Enrollment codes (deliver a fresh start token to a service server without a
// person ever seeing it) and client lists (the environment's clients and
// generated secrets as reviewed JSON, applied in one step).

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"secrets-manager/internal/crypto"
	"secrets-manager/internal/store"
)

const (
	enrollPrefix = "sme_"
	enrollTTL    = 15 * time.Minute
)

type enrollment struct {
	clientID string
	expires  time.Time
}

// enrollClient (admin) creates a one-time code for a client. Exchanging it
// rotates the client's start token; the previous token keeps working for the
// grace period, so running containers are not interrupted.
func (s *Server) enrollClient(w http.ResponseWriter, r *http.Request, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.vault.State.Clients[r.PathValue("id")]
	if !ok || c.RevokedAt != nil {
		fail(w, 404, "not found")
		return
	}
	random, err := crypto.RandomString("base64url", 32)
	if err != nil {
		fail(w, 500, "internal error")
		return
	}
	code := enrollPrefix + random
	now := s.cfg.Now()
	for k, e := range s.enrollments { // one open code per client; expired ones dropped
		if e.clientID == c.ID || !now.Before(e.expires) {
			delete(s.enrollments, k)
		}
	}
	expires := now.Add(enrollTTL)
	s.enrollments[string(crypto.MAC(s.vault.State.ServerKey, code))] = enrollment{clientID: c.ID, expires: expires}
	s.record("admin:"+user, "client.enroll_code", "", 0, true, c.Name)
	writeJSON(w, 201, map[string]any{"code": code, "expires_at": expires, "client": c.Name})
}

// exchangeEnrollment turns a one-time code into a new start token (once).
func (s *Server) exchangeEnrollment(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.authLimit.allow(ip, s.cfg.Now()) {
		w.Header().Set("Retry-After", "60")
		fail(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		fail(w, http.StatusServiceUnavailable, "sealed")
		return
	}
	key := string(crypto.MAC(s.vault.State.ServerKey, bearer(r)))
	e, ok := s.enrollments[key]
	delete(s.enrollments, key) // single use, also when expired
	now := s.cfg.Now()
	var c *store.Client
	if ok && now.Before(e.expires) {
		c = s.vault.State.Clients[e.clientID]
	}
	if c == nil || c.RevokedAt != nil {
		s.authLimit.failed(ip, now)
		s.record("anonymous", "client.enroll", "", 0, false, "invalid or expired code")
		fail(w, 401, "unauthorized")
		return
	}
	random, err := crypto.RandomString("base64url", 32)
	if err != nil {
		fail(w, 500, "internal error")
		return
	}
	token := tokenPrefix + random
	until := now.Add(s.cfg.GracePeriod)
	c.PrevTokenMAC, c.PrevUntil = c.TokenMAC, &until
	c.TokenMAC = crypto.MAC(s.vault.State.ServerKey, token)
	if err := s.vault.Save(); err != nil {
		fail(w, 500, "save failed")
		return
	}
	s.record("client:"+c.Name, "client.enroll", "", 0, true, "start token rotated")
	writeJSON(w, 200, map[string]any{"client": c.Name, "token": token})
}

// ---------------------------------------------------------------- client lists

// ClientList is one environment's reviewed setup (no secret values).
type ClientList struct {
	Environment string `json:"environment"`
	Secrets     []struct {
		Path     string `json:"path"`
		Kind     string `json:"kind"` // generated: created here; static: entered by the commander
		Alphabet string `json:"alphabet,omitempty"`
		Length   int    `json:"length,omitempty"`
		Note     string `json:"note,omitempty"`
	} `json:"secrets"`
	Clients []struct {
		Name     string   `json:"name"`
		Policies []string `json:"policies"`
		PKINames []string `json:"pki_names"`
	} `json:"clients"`
}

type applyReport struct {
	CreatedClients   []string `json:"created_clients"`
	UpdatedClients   []string `json:"updated_clients"`
	CreatedSecrets   []string `json:"created_secrets"`
	MissingStatic    []string `json:"missing_static"`      // to be entered in the UI
	NotInList        []string `json:"clients_not_in_list"` // never deleted automatically
	UnchangedClients int      `json:"unchanged_clients"`
}

func (l *ClientList) validate(environment string) error {
	if l.Environment != environment {
		return errors.New("list is for environment " + l.Environment + ", this vault is " + environment)
	}
	if len(l.Secrets) > 500 || len(l.Clients) > 200 {
		return errors.New("list too long")
	}
	for _, sec := range l.Secrets {
		if !store.ValidPath(sec.Path) || len(sec.Note) > 300 {
			return errors.New("invalid secret " + sec.Path)
		}
		if sec.Kind != "static" && sec.Kind != "generated" {
			return errors.New(sec.Path + ": kind must be static or generated")
		}
	}
	names := map[string]bool{}
	for _, c := range l.Clients {
		if !clientName.MatchString(c.Name) || names[c.Name] {
			return errors.New("invalid or duplicate client " + c.Name)
		}
		names[c.Name] = true
		if len(c.Policies) > 20 || len(c.Policies) == 0 && len(c.PKINames) == 0 || !validPKINames(c.PKINames) {
			return errors.New(c.Name + ": invalid policies or certificate names")
		}
		for _, p := range c.Policies {
			if !policyPattern.MatchString(p) {
				return errors.New(c.Name + ": invalid policy " + p)
			}
		}
	}
	return nil
}

// applyClientList creates missing clients and generated secrets and updates
// the policies / certificate names of listed clients. It never deletes and
// never reveals values; new clients get their start token via enrollment.
func (s *Server) applyClientList(w http.ResponseWriter, r *http.Request, user string) {
	var list ClientList
	if err := readJSON(r, &list); err != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	if err := list.validate(s.cfg.Environment); err != nil {
		fail(w, 422, err.Error())
		return
	}
	actor := "admin:" + user
	s.mu.Lock()
	defer s.mu.Unlock()
	st, now := s.vault.State, s.cfg.Now()
	report := applyReport{CreatedClients: []string{}, UpdatedClients: []string{}, CreatedSecrets: []string{}, MissingStatic: []string{}, NotInList: []string{}}

	for _, want := range list.Secrets {
		sec, exists := st.Secrets[want.Path]
		switch {
		case exists:
			continue
		case want.Kind == "static":
			report.MissingStatic = append(report.MissingStatic, want.Path)
			continue
		}
		alphabet, length := want.Alphabet, want.Length
		if alphabet == "" {
			alphabet = "alnum"
		}
		if length == 0 {
			length = 40
		}
		value, err := crypto.RandomString(alphabet, length)
		if err != nil {
			fail(w, 422, want.Path+": "+err.Error())
			return
		}
		sec = &store.Secret{Kind: "generated", Alphabet: alphabet, Length: length, Note: want.Note, CreatedAt: now}
		version := sec.PutVersion(value, actor, now)
		st.Secrets[want.Path] = sec
		report.CreatedSecrets = append(report.CreatedSecrets, want.Path)
		s.record(actor, "secret.set", want.Path, version.Number, true, "generated (client list)")
	}

	listed := map[string]bool{}
	for _, want := range list.Clients {
		listed[want.Name] = true
		var existing *store.Client
		for _, c := range st.Clients {
			if c.Name == want.Name && c.RevokedAt == nil {
				existing = c
			}
		}
		if existing == nil {
			id, err := crypto.RandomString("hex", 16)
			if err != nil {
				fail(w, 500, "internal error")
				return
			}
			// No usable start token yet (random MAC): the client is enrolled next
			placeholder, err := crypto.NewKey()
			if err != nil {
				fail(w, 500, "internal error")
				return
			}
			st.Clients[id] = &store.Client{ID: id, Name: want.Name, TokenMAC: placeholder, Policies: want.Policies, PKINames: want.PKINames, CreatedAt: now}
			report.CreatedClients = append(report.CreatedClients, want.Name)
			s.record(actor, "client.create", "", 0, true, want.Name+" (client list)")
			continue
		}
		if slices.Equal(existing.Policies, want.Policies) && slices.Equal(existing.PKINames, want.PKINames) {
			report.UnchangedClients++
			continue
		}
		existing.Policies, existing.PKINames = want.Policies, want.PKINames
		report.UpdatedClients = append(report.UpdatedClients, want.Name)
		s.record(actor, "client.update", "", 0, true, want.Name+" (client list)")
	}
	for _, c := range st.Clients {
		if c.RevokedAt == nil && !listed[c.Name] {
			report.NotInList = append(report.NotInList, c.Name)
		}
	}
	if err := s.vault.Save(); err != nil {
		fail(w, 500, "save failed")
		return
	}
	slices.Sort(report.NotInList)
	writeJSON(w, 200, report)
}
