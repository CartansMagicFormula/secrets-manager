// Package store keeps the vault state encrypted on disk.
//
// File: header (format, generation, wrapped state key) + AES-256-GCM ciphertext
// of the JSON state. The state key is wrapped with the master key, which is
// never stored. Every save uses a new nonce and generation; writes are atomic.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"secrets-manager/internal/crypto"
)

const format = "secrets-manager/v1"

// MaxVersions kept per secret.
const MaxVersions = 5

// ErrNotFound for unknown secrets / clients.
var ErrNotFound = errors.New("not found")

var pathPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}(/[a-z0-9][a-z0-9_-]{0,62}){1,4}$`)

// ValidPath reports whether a secret path is well-formed (2–5 segments).
func ValidPath(p string) bool { return pathPattern.MatchString(p) }

// Version of a secret value.
type Version struct {
	Number    int       `json:"number"`
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// Secret with its versions (newest last).
type Secret struct {
	Kind      string    `json:"kind"` // static | generated
	Alphabet  string    `json:"alphabet,omitempty"`
	Length    int       `json:"length,omitempty"`
	Note      string    `json:"note,omitempty"`
	Versions  []Version `json:"versions"`
	CreatedAt time.Time `json:"created_at"`
}

// Current version (the last one).
func (s *Secret) Current() Version { return s.Versions[len(s.Versions)-1] }

// Previous version, if any.
func (s *Secret) Previous() (Version, bool) {
	if len(s.Versions) < 2 {
		return Version{}, false
	}
	return s.Versions[len(s.Versions)-2], true
}

// Client is a service allowed to read some paths.
type Client struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	TokenMAC   []byte     `json:"token_mac"`
	Policies   []string   `json:"policies"` // path prefixes, read-only
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// Allows reports whether the client may read path (prefix on segment boundary).
func (c *Client) Allows(path string) bool {
	if c.RevokedAt != nil {
		return false
	}
	for _, p := range c.Policies {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// Admin account.
type Admin struct {
	Username   string    `json:"username"`
	Salt       []byte    `json:"salt"`
	Hash       []byte    `json:"hash"`
	Iterations int       `json:"iterations"`
	CreatedAt  time.Time `json:"created_at"`
}

// State is everything the vault knows (encrypted at rest).
type State struct {
	ServerKey []byte             `json:"server_key"` // HMAC key for client tokens
	Admin     Admin              `json:"admin"`
	Secrets   map[string]*Secret `json:"secrets"`
	Clients   map[string]*Client `json:"clients"`
}

// SecretPaths sorted.
func (s *State) SecretPaths() []string {
	paths := make([]string, 0, len(s.Secrets))
	for p := range s.Secrets {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// PutVersion appends a new version (oldest dropped beyond MaxVersions).
func (s *Secret) PutVersion(value, actor string, now time.Time) Version {
	number := 1
	if len(s.Versions) > 0 {
		number = s.Current().Number + 1
	}
	v := Version{Number: number, Value: value, CreatedAt: now, CreatedBy: actor}
	s.Versions = append(s.Versions, v)
	if len(s.Versions) > MaxVersions {
		s.Versions = s.Versions[len(s.Versions)-MaxVersions:]
	}
	return v
}

type file struct {
	Format     string         `json:"format"`
	Generation uint64         `json:"generation"`
	WrappedKey *crypto.Sealed `json:"wrapped_key"`
	State      *crypto.Sealed `json:"state"`
}

func keyAAD() []byte { return []byte(format + "|state-key") }

func stateAAD(generation uint64) []byte {
	return []byte(fmt.Sprintf("%s|state|%d", format, generation))
}

// Vault is an unsealed store: keys in memory, state decrypted.
type Vault struct {
	path       string
	masterKey  []byte
	stateKey   []byte
	generation uint64
	State      *State
}

// Exists reports whether the state file exists (initialized).
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Create initializes a new vault file; fails if one exists.
func Create(path string, admin Admin) (*Vault, []byte, error) {
	if Exists(path) {
		return nil, nil, errors.New("already initialized")
	}
	master, err := crypto.NewKey()
	if err != nil {
		return nil, nil, err
	}
	stateKey, err := crypto.NewKey()
	if err != nil {
		return nil, nil, err
	}
	serverKey, err := crypto.NewKey()
	if err != nil {
		return nil, nil, err
	}
	v := &Vault{
		path:      path,
		masterKey: master,
		stateKey:  stateKey,
		State:     &State{ServerKey: serverKey, Admin: admin, Secrets: map[string]*Secret{}, Clients: map[string]*Client{}},
	}
	if err := v.Save(); err != nil {
		return nil, nil, err
	}
	return v, master, nil
}

// Open decrypts the vault with the master key.
func Open(path string, master []byte) (*Vault, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(raw, &f); err != nil || f.Format != format {
		return nil, errors.New("invalid state file")
	}
	stateKey, err := crypto.Open(master, f.WrappedKey, keyAAD())
	if err != nil {
		return nil, crypto.ErrDecrypt
	}
	plain, err := crypto.Open(stateKey, f.State, stateAAD(f.Generation))
	if err != nil {
		return nil, crypto.ErrDecrypt
	}
	var st State
	if err := json.Unmarshal(plain, &st); err != nil {
		return nil, errors.New("invalid state")
	}
	if st.Secrets == nil {
		st.Secrets = map[string]*Secret{}
	}
	if st.Clients == nil {
		st.Clients = map[string]*Client{}
	}
	return &Vault{path: path, masterKey: master, stateKey: stateKey, generation: f.Generation, State: &st}, nil
}

// Save encrypts and writes the state atomically (temp file, fsync, rename).
func (v *Vault) Save() error {
	plain, err := json.Marshal(v.State)
	if err != nil {
		return err
	}
	generation := v.generation + 1
	sealedState, err := crypto.Seal(v.stateKey, plain, stateAAD(generation))
	if err != nil {
		return err
	}
	wrapped, err := crypto.Seal(v.masterKey, v.stateKey, keyAAD())
	if err != nil {
		return err
	}
	raw, err := json.Marshal(file{Format: format, Generation: generation, WrappedKey: wrapped, State: sealedState})
	if err != nil {
		return err
	}
	dir := filepath.Dir(v.path)
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), v.path); err != nil {
		return err
	}
	v.generation = generation
	return nil
}

// ChangeMasterKey re-wraps the state key with a new master key (returned once).
func (v *Vault) ChangeMasterKey() ([]byte, error) {
	next, err := crypto.NewKey()
	if err != nil {
		return nil, err
	}
	old := v.masterKey
	v.masterKey = next
	if err := v.Save(); err != nil {
		v.masterKey = old
		return nil, err
	}
	return next, nil
}

// Close drops the keys from memory (best effort: Go cannot guarantee zeroing copies).
func (v *Vault) Close() {
	for i := range v.masterKey {
		v.masterKey[i] = 0
	}
	for i := range v.stateKey {
		v.stateKey[i] = 0
	}
	v.State = nil
}

// Generation of the last save.
func (v *Vault) Generation() uint64 { return v.generation }
