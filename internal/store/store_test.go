package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secrets-manager/internal/crypto"
)

func newVault(t *testing.T) (*Vault, []byte, string) {
	path := filepath.Join(t.TempDir(), "state.json")
	v, master, err := Create(path, Admin{Username: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	return v, master, path
}

func TestCreateOpenRoundtrip(t *testing.T) {
	v, master, path := newVault(t)
	s := &Secret{Kind: "static", CreatedAt: time.Now()}
	s.PutVersion("sk_test_123", "admin:admin", time.Now())
	v.State.Secrets["llm-gateway/anthropic"] = s
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "sk_test_123") || strings.Contains(string(raw), "anthropic") {
		t.Fatal("plaintext on disk")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v", info.Mode().Perm())
	}
	v2, err := Open(path, master)
	if err != nil {
		t.Fatal(err)
	}
	if v2.State.Secrets["llm-gateway/anthropic"].Current().Value != "sk_test_123" || v2.Generation() != 2 {
		t.Fatal("state not restored")
	}
	if _, _, err := Create(path, Admin{}); err == nil {
		t.Fatal("re-init allowed")
	}
}

func TestWrongKeyAndTampering(t *testing.T) {
	_, _, path := newVault(t)
	wrong, _ := crypto.NewKey()
	if _, err := Open(path, wrong); err != crypto.ErrDecrypt {
		t.Fatal("wrong key accepted")
	}
	// Changing the generation in the header breaks authentication (bound as AAD)
	_, master, path2 := newVault(t)
	raw, _ := os.ReadFile(path2)
	var f map[string]any
	_ = json.Unmarshal(raw, &f)
	f["generation"] = 99
	raw, _ = json.Marshal(f)
	_ = os.WriteFile(path2, raw, 0o600)
	if _, err := Open(path2, master); err != crypto.ErrDecrypt {
		t.Fatal("tampered header accepted")
	}
}

func TestChangeMasterKey(t *testing.T) {
	v, old, path := newVault(t)
	next, err := v.ChangeMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, old); err == nil {
		t.Fatal("old master key still works")
	}
	if _, err := Open(path, next); err != nil {
		t.Fatal("new master key rejected")
	}
}

func TestVersionsAndPolicies(t *testing.T) {
	s := &Secret{Kind: "generated"}
	for i := 0; i < 8; i++ {
		s.PutVersion("v", "system", time.Now())
	}
	if len(s.Versions) != MaxVersions || s.Current().Number != 8 {
		t.Fatalf("versions: %d, current %d", len(s.Versions), s.Current().Number)
	}
	if prev, ok := s.Previous(); !ok || prev.Number != 7 {
		t.Fatal("previous version")
	}
	c := &Client{Policies: []string{"llm-gateway", "osiris/stripe"}}
	cases := map[string]bool{
		"llm-gateway/anthropic": true,
		"llm-gateway-evil/x":    false, // prefix only on segment boundary
		"osiris/stripe":         true,
		"osiris/stripe/webhook": true,
		"osiris/smtp":           false,
	}
	for path, want := range cases {
		if c.Allows(path) != want {
			t.Errorf("%s: want %v", path, want)
		}
	}
	now := time.Now()
	c.RevokedAt = &now
	if c.Allows("llm-gateway/anthropic") {
		t.Fatal("revoked client allowed")
	}
}

func TestValidPath(t *testing.T) {
	for _, p := range []string{"a/b", "llm-gateway/anthropic_key", "a/b/c/d/e"} {
		if !ValidPath(p) {
			t.Errorf("%s should be valid", p)
		}
	}
	for _, p := range []string{"a", "A/b", "a/../b", "/a/b", "a/b/", "a/b/c/d/e/f", "a//b"} {
		if ValidPath(p) {
			t.Errorf("%s should be invalid", p)
		}
	}
}
