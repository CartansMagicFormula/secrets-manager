package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestSealOpen(t *testing.T) {
	key, _ := NewKey()
	s, err := Seal(key, []byte("top secret"), []byte("ctx|1"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, s, []byte("ctx|1"))
	if err != nil || string(got) != "top secret" {
		t.Fatalf("roundtrip: %q %v", got, err)
	}
	other, _ := NewKey()
	if _, err := Open(other, s, []byte("ctx|1")); err != ErrDecrypt {
		t.Fatal("wrong key accepted")
	}
	if _, err := Open(key, s, []byte("ctx|2")); err != ErrDecrypt {
		t.Fatal("wrong associated data accepted (swap / rollback protection)")
	}
	tampered := &Sealed{Nonce: s.Nonce, Ciphertext: append([]byte{}, s.Ciphertext...)}
	tampered.Ciphertext[0] ^= 1
	if _, err := Open(key, tampered, []byte("ctx|1")); err != ErrDecrypt {
		t.Fatal("tampered ciphertext accepted")
	}
	if _, err := Open(key, &Sealed{Nonce: []byte{1}}, nil); err != ErrDecrypt {
		t.Fatal("short nonce accepted")
	}
	if _, err := Seal([]byte("short"), []byte("x"), nil); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestNoncesAreFresh(t *testing.T) {
	key, _ := NewKey()
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		s, _ := Seal(key, []byte("same"), nil)
		if seen[string(s.Nonce)] {
			t.Fatal("nonce reused")
		}
		seen[string(s.Nonce)] = true
	}
}

func TestPassword(t *testing.T) {
	salt, hash, err := PasswordHash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !PasswordVerify("correct horse battery", salt, hash, PasswordIterations) {
		t.Fatal("valid password rejected")
	}
	if PasswordVerify("wrong", salt, hash, PasswordIterations) {
		t.Fatal("wrong password accepted")
	}
	salt2, hash2, _ := PasswordHash("correct horse battery")
	if bytes.Equal(salt, salt2) || bytes.Equal(hash, hash2) {
		t.Fatal("salt not random")
	}
}

func TestRandomString(t *testing.T) {
	for _, alphabet := range []string{"alnum", "hex"} {
		s, err := RandomString(alphabet, 40)
		if err != nil || len(s) != 40 {
			t.Fatalf("%s: %q %v", alphabet, s, err)
		}
		for _, c := range s {
			if !strings.ContainsRune(Alphabets[alphabet], c) {
				t.Fatalf("%s: unexpected %q", alphabet, c)
			}
		}
	}
	b, err := RandomString("base64url", 32)
	if err != nil || len(b) != 43 {
		t.Fatalf("base64url: %q %v", b, err)
	}
	if _, err := RandomString("alnum", 8); err == nil {
		t.Fatal("too short accepted")
	}
	if _, err := RandomString("emoji", 32); err == nil {
		t.Fatal("unknown alphabet accepted")
	}
	// Rough uniformity: every alnum character appears in a large sample
	big, _ := RandomString("alnum", 256)
	sample := big
	for i := 0; i < 40; i++ {
		more, _ := RandomString("alnum", 256)
		sample += more
	}
	for _, c := range Alphabets["alnum"] {
		if !strings.ContainsRune(sample, c) {
			t.Fatalf("character %q never drawn", c)
		}
	}
}

func TestKeyEncoding(t *testing.T) {
	key, _ := NewKey()
	got, err := DecodeKey(" " + EncodeKey(key) + "\n")
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("key encoding roundtrip")
	}
	if _, err := DecodeKey("abc"); err == nil {
		t.Fatal("short key accepted")
	}
}
