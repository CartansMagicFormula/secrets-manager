// sm-agent: fetches certificates and secrets from the secrets manager into
// files for services that cannot talk to the vault themselves (Postgres,
// Valkey, SeaweedFS, Keycloak, …). Runs as a sidecar (renews in a loop) or
// with -once as an init container. Standard library only.
//
// Environment: SM_URL (https://secrets-manager:8443), SM_CA_FILE (fleet CA),
// SM_TOKEN_FILE (start token), SM_INSTANCE (default: hostname).
//
//	sm-agent -cert postgres,lumen-postgres-1 -cert-dir /certs \
//	         -secret lumen/db-app-password=db_app_password -secret-dir /run/sm \
//	         -reload-pid 1 -reload-signal HUP
//
// Files: <cert-dir>/tls.key (0600, generated here, never sent), tls.crt
// (certificate + CA), ca.crt; one file per secret (0400). Writes are atomic.
//
// Entrypoint mode (images without a shell): fetch once, then start the service
// in place of sm-agent:
//
//	sm-agent -once -secret osiris/analyzer/token=analyzer_token -secret-dir /run/vault -- /osiris-analyzer
//
// Enrollment (once per client, run by the commander on the service server):
//
//	docker run --rm -i --user <uid of the service> -v <token volume>:/tokens ... \
//	  secrets-manager:latest /sm-agent enroll -out /tokens/<client>
//
// reads the one-time code from stdin and writes the new start token (0400).
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"secrets-manager/internal/client"
)

type secretFlags []string

func (s *secretFlags) String() string     { return strings.Join(*s, ",") }
func (s *secretFlags) Set(v string) error { *s = append(*s, v); return nil }

var fileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

type options struct {
	certNames    []string
	certDir      string
	usage        string
	ttl          time.Duration
	secrets      map[string]string // path -> file name
	secretDir    string
	interval     time.Duration
	reloadPID    int
	reloadSignal syscall.Signal
	once         bool
	exec         []string // with -once: the service command started afterwards (replaces sm-agent)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sm-agent-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// certDue reports whether the certificate is missing or past 2/3 of its lifetime.
func certDue(path string, now time.Time) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	life := cert.NotAfter.Sub(cert.NotBefore)
	return now.After(cert.NotBefore.Add(life * 2 / 3))
}

// renewCert creates a new key and CSR, gets it signed and writes the files.
func renewCert(c *client.Client, o options) (bool, error) {
	crtPath := filepath.Join(o.certDir, "tls.crt")
	if !certDue(crtPath, time.Now()) {
		return false, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, err
	}
	tmpl := &x509.CertificateRequest{}
	if o.usage == "client" {
		tmpl.Subject = pkix.Name{CommonName: o.certNames[0]}
	} else {
		for _, n := range o.certNames {
			if ip := net.ParseIP(n); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			} else {
				tmpl.DNSNames = append(tmpl.DNSNames, n)
			}
		}
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return false, err
	}
	issued, err := c.Issue(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), o.usage, o.ttl)
	if err != nil {
		return false, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return false, err
	}
	// Key first, then certificate: a reader never sees a new cert with an old key for long
	if err := writeAtomic(filepath.Join(o.certDir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return false, err
	}
	if err := writeAtomic(filepath.Join(o.certDir, "ca.crt"), []byte(issued.CAPEM), 0o644); err != nil {
		return false, err
	}
	if err := writeAtomic(crtPath, []byte(issued.CertPEM+issued.CAPEM), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// syncSecrets writes changed secret values; reports whether anything changed.
func syncSecrets(c *client.Client, o options) (bool, error) {
	changed := false
	for path, name := range o.secrets {
		value, err := c.Get(path, false)
		if err != nil {
			return changed, fmt.Errorf("%s: %w", path, err)
		}
		target := filepath.Join(o.secretDir, name)
		if old, err := os.ReadFile(target); err == nil && string(old) == value {
			continue
		}
		if err := writeAtomic(target, []byte(value), 0o400); err != nil {
			return changed, fmt.Errorf("%s: write failed", path)
		}
		changed = true
	}
	return changed, nil
}

func parse(args []string) (options, error) {
	fs := flag.NewFlagSet("sm-agent", flag.ContinueOnError)
	var secretArgs secretFlags
	certNames := fs.String("cert", "", "comma-separated names (server: DNS names / IPs; client: the common name)")
	o := options{secrets: map[string]string{}}
	fs.StringVar(&o.certDir, "cert-dir", "/certs", "where tls.key, tls.crt, ca.crt are written")
	fs.StringVar(&o.usage, "usage", "server", "server or client certificate")
	fs.DurationVar(&o.ttl, "ttl", 30*24*time.Hour, "certificate lifetime (renewed after 2/3)")
	fs.Var(&secretArgs, "secret", "path=file (repeatable)")
	fs.StringVar(&o.secretDir, "secret-dir", "/run/sm", "where secret files are written (use tmpfs)")
	fs.DurationVar(&o.interval, "interval", 5*time.Minute, "check interval")
	fs.IntVar(&o.reloadPID, "reload-pid", 0, "send a signal to this PID after a change (shared PID namespace)")
	signal := fs.String("reload-signal", "HUP", "HUP or TERM")
	fs.BoolVar(&o.once, "once", false, "run once and exit (init container)")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	o.exec = fs.Args()
	if len(o.exec) > 0 && !o.once {
		return o, errors.New("a command to start needs -once")
	}
	if *certNames != "" {
		o.certNames = strings.Split(*certNames, ",")
	}
	for _, s := range secretArgs {
		path, name, ok := strings.Cut(s, "=")
		if !ok || !fileName.MatchString(name) || path == "" {
			return o, fmt.Errorf("-secret %q: expected path=file", s)
		}
		o.secrets[path] = name
	}
	if len(o.certNames) == 0 && len(o.secrets) == 0 {
		return o, errors.New("nothing to do: give -cert and/or -secret")
	}
	if o.usage != "server" && o.usage != "client" {
		return o, errors.New("-usage must be server or client")
	}
	switch *signal {
	case "HUP":
		o.reloadSignal = syscall.SIGHUP
	case "TERM":
		o.reloadSignal = syscall.SIGTERM
	default:
		return o, errors.New("-reload-signal must be HUP or TERM")
	}
	if o.interval < 10*time.Second {
		return o, errors.New("-interval must be at least 10s")
	}
	return o, nil
}

func run(logger *slog.Logger, c *client.Client, o options) bool {
	changed, ok := false, true
	if len(o.certNames) > 0 {
		renewed, err := renewCert(c, o)
		if err != nil {
			logger.Error("certificate renewal failed", "error", err.Error())
			ok = false
		} else if renewed {
			logger.Info("certificate renewed", "names", strings.Join(o.certNames, ","))
			changed = true
		}
	}
	if len(o.secrets) > 0 {
		updated, err := syncSecrets(c, o)
		if err != nil {
			logger.Error("secret sync failed", "error", err.Error())
			ok = false
		}
		if updated {
			logger.Info("secrets updated")
			changed = true
		}
	}
	if changed && o.reloadPID > 0 {
		if err := syscall.Kill(o.reloadPID, o.reloadSignal); err != nil {
			logger.Error("reload signal failed", "pid", o.reloadPID)
		} else {
			logger.Info("reload signalled", "pid", o.reloadPID)
		}
	}
	return ok
}

// startService replaces sm-agent with the service (same PID, so the service is
// PID 1 and gets Docker's signals). For images without a shell: the files are
// written before the service starts.
func startService(logger *slog.Logger, command []string) {
	path := command[0]
	if !strings.Contains(path, "/") {
		found, err := exec.LookPath(path)
		if err != nil {
			logger.Error("command not found", "command", path)
			os.Exit(127)
		}
		path = found
	}
	err := syscall.Exec(path, command, os.Environ())
	logger.Error("starting the service failed", "command", path, "error", err.Error())
	os.Exit(126)
}

// enroll exchanges a one-time code (read from stdin) for a start token file.
func enroll(args []string, stdin io.Reader) error {
	fs := flag.NewFlagSet("sm-agent enroll", flag.ContinueOnError)
	out := fs.String("out", "", "where the start token is written (0400)")
	owner := fs.String("owner", "", "uid:gid that gets the token file (run as root with CAP_CHOWN): the service's user")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-out is required")
	}
	uid, gid := -1, -1
	if *owner != "" {
		u, g, ok := strings.Cut(*owner, ":")
		var errU, errG error
		uid, errU = strconv.Atoi(u)
		gid, errG = strconv.Atoi(g)
		if !ok || errU != nil || errG != nil || uid < 0 || gid < 0 {
			return errors.New("-owner must be uid:gid")
		}
	}
	c, err := client.New(os.Getenv("SM_URL"), os.Getenv("SM_CA_FILE"), *out, os.Getenv("SM_INSTANCE"))
	if err != nil {
		return err
	}
	code, err := bufio.NewReader(io.LimitReader(stdin, 1024)).ReadString('\n')
	if err != nil && code == "" {
		return errors.New("no enrollment code on stdin")
	}
	token, err := c.Enroll(code)
	if err != nil {
		return err
	}
	if err := writeAtomic(*out, []byte(token+"\n"), 0o400); err != nil {
		return err
	}
	if uid >= 0 {
		return os.Chown(*out, uid, gid)
	}
	return nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if len(os.Args) > 1 && os.Args[1] == "enroll" {
		if err := enroll(os.Args[2:], os.Stdin); err != nil {
			logger.Error("enrollment failed", "error", err.Error())
			os.Exit(1)
		}
		logger.Info("start token written")
		return
	}
	o, err := parse(os.Args[1:])
	if err != nil {
		logger.Error("invalid arguments", "error", err.Error())
		os.Exit(2)
	}
	c, err := client.New(os.Getenv("SM_URL"), os.Getenv("SM_CA_FILE"), os.Getenv("SM_TOKEN_FILE"), os.Getenv("SM_INSTANCE"))
	if err != nil {
		logger.Error("client setup failed", "error", err.Error())
		os.Exit(1)
	}
	if o.once {
		// Init container: retry until the vault answers (it may still be sealed)
		for delay := time.Second; !run(logger, c, o); delay = min(delay*2, 30*time.Second) {
			time.Sleep(delay)
		}
		if len(o.exec) > 0 {
			startService(logger, o.exec)
		}
		return
	}
	for {
		delay := o.interval
		if !run(logger, c, o) {
			delay = 15 * time.Second
		}
		time.Sleep(delay)
	}
}
