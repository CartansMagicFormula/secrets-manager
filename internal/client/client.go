// Package client talks to the secrets manager as a service (used by sm-agent;
// Go services copy this file, see docs/clients.md).
//
// Flow: start token (file) → POST /v1/auth/login → access token in memory,
// renewed before it expires, a fresh login after the maximum lifetime or a
// vault restart. TLS 1.3 against the fleet CA only. Values are never logged.
package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ErrNoPrevious when no previous version is in its grace period.
var ErrNoPrevious = errors.New("no previous version")

// ErrSealed while the vault is sealed (retry later).
var ErrSealed = errors.New("vault is sealed")

// Client of the secrets manager.
type Client struct {
	URL       string // e.g. https://secrets-manager:8443
	TokenFile string // start token
	Instance  string // container instance (hostname)
	HTTP      *http.Client
	Now       func() time.Time

	mu       sync.Mutex
	access   string
	expires  time.Time
	maxUntil time.Time
}

// New builds a client that trusts only the CA in caFile.
func New(url, caFile, tokenFile, instance string) (*Client, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, errors.New("CA file unreadable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("CA file contains no certificate")
	}
	if instance == "" {
		instance, _ = os.Hostname()
	}
	return &Client{
		URL: strings.TrimRight(url, "/"), TokenFile: tokenFile, Instance: instance,
		HTTP: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
		}},
	}, nil
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) call(method, path, token string, body any, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.URL+path, reader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, errors.New("vault unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		return resp.StatusCode, ErrSealed
	}
	if out != nil && resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(out); err != nil {
			return resp.StatusCode, errors.New("unusable answer")
		}
	}
	return resp.StatusCode, nil
}

// token returns a valid access token: logs in or renews when needed.
func (c *Client) token() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.access != "" && now.Before(c.expires.Add(-5*time.Minute)) {
		return c.access, nil
	}
	if c.access != "" && now.Before(c.expires) && now.Before(c.maxUntil.Add(-5*time.Minute)) {
		var out struct {
			Expires time.Time `json:"expires_at"`
		}
		if code, err := c.call("POST", "/v1/auth/renew", c.access, nil, &out); err == nil && code == 200 {
			c.expires = out.Expires
			return c.access, nil
		}
	}
	return c.login()
}

func (c *Client) login() (string, error) {
	raw, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return "", errors.New("start token file unreadable")
	}
	var out struct {
		Access   string    `json:"access_token"`
		Expires  time.Time `json:"expires_at"`
		MaxUntil time.Time `json:"max_until"`
	}
	code, err := c.call("POST", "/v1/auth/login", strings.TrimSpace(string(raw)), map[string]string{"instance": c.Instance}, &out)
	if err != nil {
		return "", err
	}
	if code != 200 || out.Access == "" {
		return "", fmt.Errorf("login refused (%d)", code)
	}
	c.access, c.expires, c.maxUntil = out.Access, out.Expires, out.MaxUntil
	return c.access, nil
}

// do runs an authenticated call, logging in again once on 401 (vault restarted).
func (c *Client) do(method, path string, body, out any) (int, error) {
	for attempt := 0; attempt < 2; attempt++ {
		token, err := c.token()
		if err != nil {
			return 0, err
		}
		code, err := c.call(method, path, token, body, out)
		if err != nil || code != http.StatusUnauthorized {
			return code, err
		}
		c.mu.Lock()
		c.access = ""
		c.mu.Unlock()
	}
	return http.StatusUnauthorized, errors.New("unauthorized")
}

// Get returns a secret value; previous=true asks for the previous version.
func (c *Client) Get(path string, previous bool) (string, error) {
	url := "/v1/secrets/" + path
	if previous {
		url += "?version=previous"
	}
	var out struct {
		Value string `json:"value"`
	}
	code, err := c.do("GET", url, nil, &out)
	switch {
	case err != nil:
		return "", err
	case code == http.StatusNotFound && previous:
		return "", ErrNoPrevious
	case code != http.StatusOK || out.Value == "":
		return "", fmt.Errorf("vault refused %s (%d)", path, code)
	}
	return out.Value, nil
}

// Enroll exchanges a one-time enrollment code (from the admin UI) for a new
// start token. The code works once and expires after 15 minutes.
func (c *Client) Enroll(code string) (string, error) {
	var out struct {
		Token string `json:"token"`
	}
	status, err := c.call("POST", "/v1/auth/enroll", strings.TrimSpace(code), nil, &out)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK || out.Token == "" {
		return "", fmt.Errorf("enrollment refused (%d): code invalid, used or expired", status)
	}
	return out.Token, nil
}

// Certificate issued by the vault.
type Certificate struct {
	CertPEM  string    `json:"certificate"`
	CAPEM    string    `json:"ca"`
	Serial   string    `json:"serial"`
	NotAfter time.Time `json:"not_after"`
}

// Issue sends a CSR (PEM) and returns the signed certificate.
func (c *Client) Issue(csrPEM []byte, usage string, ttl time.Duration) (*Certificate, error) {
	var out Certificate
	body := map[string]string{"csr": string(csrPEM), "usage": usage}
	if ttl > 0 {
		body["ttl"] = ttl.String()
	}
	code, err := c.do("POST", "/v1/pki/issue", body, &out)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("certificate refused (%d)", code)
	}
	return &out, nil
}
