// Package crypto wraps the few standard-library primitives the vault uses.
//
// No primitive is implemented here: AES-256-GCM (crypto/aes, crypto/cipher),
// PBKDF2 (crypto/pbkdf2), HMAC-SHA256 (crypto/hmac), randomness (crypto/rand).
// The rules this package enforces: 32-byte keys only, a fresh random nonce for
// every encryption, associated data on every ciphertext, constant-time compares.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// KeySize of every symmetric key (AES-256).
const KeySize = 32

// PasswordIterations for PBKDF2-HMAC-SHA256 (OWASP 2023 recommendation).
const PasswordIterations = 600_000

// ErrDecrypt hides why decryption failed (wrong key, tampering, wrong context).
var ErrDecrypt = errors.New("decryption failed")

// Sealed is a ciphertext with its nonce.
type Sealed struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// NewKey returns a random 32-byte key.
func NewKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must be %d bytes", KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plaintext with a fresh random nonce, bound to the associated data.
func Seal(key, plaintext, associated []byte) (*Sealed, error) {
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &Sealed{Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plaintext, associated)}, nil
}

// Open decrypts and authenticates; any failure is ErrDecrypt.
func Open(key []byte, s *Sealed, associated []byte) ([]byte, error) {
	aead, err := gcm(key)
	if err != nil {
		return nil, ErrDecrypt
	}
	if s == nil || len(s.Nonce) != aead.NonceSize() {
		return nil, ErrDecrypt
	}
	out, err := aead.Open(nil, s.Nonce, s.Ciphertext, associated)
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}

// PasswordHash derives a hash with a fresh 16-byte salt.
func PasswordHash(password string) (salt, hash []byte, err error) {
	salt = make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return nil, nil, err
	}
	hash, err = pbkdf2.Key(sha256.New, password, salt, PasswordIterations, KeySize)
	return salt, hash, err
}

// PasswordVerify compares in constant time.
func PasswordVerify(password string, salt, hash []byte, iterations int) bool {
	got, err := pbkdf2.Key(sha256.New, password, salt, iterations, KeySize)
	return err == nil && subtle.ConstantTimeCompare(got, hash) == 1
}

// MAC is HMAC-SHA256 (token storage).
func MAC(key []byte, value string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(value))
	return m.Sum(nil)
}

// MACEqual compares two MACs in constant time.
func MACEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}

// Alphabets for generated values.
var Alphabets = map[string]string{
	"alnum": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	"hex":   "0123456789abcdef",
}

// RandomString draws length characters uniformly from the alphabet
// (rejection sampling, no modulo bias). "base64url" returns raw URL-safe
// base64 of length bytes of randomness.
func RandomString(alphabet string, length int) (string, error) {
	if length < 16 || length > 256 {
		return "", errors.New("length must be between 16 and 256")
	}
	if alphabet == "base64url" {
		b := make([]byte, length)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	chars, ok := Alphabets[alphabet]
	if !ok {
		return "", fmt.Errorf("unknown alphabet %q", alphabet)
	}
	limit := 256 - 256%len(chars) // largest multiple of len(chars) <= 256
	var out strings.Builder
	buf := make([]byte, 64)
	for out.Len() < length {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if int(b) < limit && out.Len() < length {
				out.WriteByte(chars[int(b)%len(chars)])
			}
		}
	}
	return out.String(), nil
}

// EncodeKey / DecodeKey: how the master key is shown to the commander.
func EncodeKey(key []byte) string { return base64.RawURLEncoding.EncodeToString(key) }

// DecodeKey accepts the encoded master key (whitespace ignored).
func DecodeKey(s string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(key) != KeySize {
		return nil, errors.New("invalid key")
	}
	return key, nil
}
