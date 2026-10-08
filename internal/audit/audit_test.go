package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := l.Write("admin:a", "secret.set", "a/b", i+1, true, ""); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := l.Verify(); err != nil || n != 5 {
		t.Fatalf("verify: %d %v", n, err)
	}
	// Reopen continues the chain
	l2, _ := Open(path)
	_ = l2.Write("client:x", "secret.read", "a/b", 5, true, "")
	if n, err := l2.Verify(); err != nil || n != 6 {
		t.Fatalf("after reopen: %d %v", n, err)
	}
	tail, _ := l2.Tail(2)
	if len(tail) != 2 || tail[0].Action != "secret.read" {
		t.Fatalf("tail: %+v", tail)
	}

	// Editing a line breaks the chain
	raw, _ := os.ReadFile(path)
	edited := strings.Replace(string(raw), `"actor":"client:x"`, `"actor":"client:y"`, 1)
	_ = os.WriteFile(path, []byte(edited), 0o600)
	if _, err := l2.Verify(); err == nil {
		t.Fatal("edited entry not detected")
	}

	// Removing a line breaks the chain
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	_ = os.WriteFile(path, []byte(strings.Join(append(lines[:2], lines[3:]...), "\n")+"\n"), 0o600)
	if _, err := l2.Verify(); err == nil {
		t.Fatal("removed entry not detected")
	}
}
