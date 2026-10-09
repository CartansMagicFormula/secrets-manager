package main

// Admin commands for scripted setup (fleet.sh). They run inside the vault
// container (`docker exec -i <vault> /secrets-manager admin …`) and talk to the
// vault over its own loopback, so the master key and the admin password never
// cross a network. Secrets come on stdin, never as arguments (process lists,
// shell history); nothing secret is printed except the new master key on init.
//
//	admin status                          initialized=… sealed=… environment=…
//	admin init -user NAME                 stdin: admin password; prints the master key
//	admin unseal                          stdin: master key
//	admin apply -user NAME                stdin: admin password, then the client list (JSON)
//	admin enroll -user NAME CLIENT...     stdin: admin password; prints "CLIENT CODE" lines

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"slices"
	"strings"
	"time"
)

type adminClient struct {
	base string
	http *http.Client
}

// newLoopbackClient: certificate verification is skipped on purpose (as in
// healthcheck): the vault serves a self-signed certificate while sealed, and
// the connection never leaves the container's loopback.
func newLoopbackClient() *adminClient {
	jar, _ := cookiejar.New(nil)
	return &adminClient{
		base: "https://127.0.0.1" + env("LISTEN_ADDR", ":8443"),
		http: &http.Client{Timeout: 30 * time.Second, Jar: jar, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		}},
	}
}

func (c *adminClient) call(method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("X-Requested-With", "secrets-manager")
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("vault unreachable")
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, e.Error)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *adminClient) login(user, password string) error {
	return c.call("POST", "/v1/admin/login", map[string]string{"username": user, "password": password}, nil)
}

// readLine reads one line from stdin (the secret), without the newline.
func readLine(in *bufio.Reader) (string, error) {
	line, err := in.ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		if err == nil {
			err = errors.New("empty")
		}
		return "", fmt.Errorf("expected a line on stdin: %w", err)
	}
	return line, nil
}

func runAdmin(c *adminClient, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: admin status|init|unseal|apply|enroll")
	}
	fs := flag.NewFlagSet("admin "+args[0], flag.ContinueOnError)
	user := fs.String("user", "", "admin username")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	in := bufio.NewReader(io.LimitReader(stdin, 1<<20))
	needUser := func() error {
		if *user == "" {
			return errors.New("-user is required")
		}
		return nil
	}

	switch args[0] {
	case "status":
		var s struct {
			Initialized bool   `json:"initialized"`
			Sealed      bool   `json:"sealed"`
			Environment string `json:"environment"`
		}
		if err := c.call("GET", "/v1/sys/status", nil, &s); err != nil {
			return err
		}
		_, err := fmt.Fprintf(stdout, "initialized=%t sealed=%t environment=%s\n", s.Initialized, s.Sealed, s.Environment)
		return err

	case "init":
		if err := needUser(); err != nil {
			return err
		}
		password, err := readLine(in)
		if err != nil {
			return err
		}
		var out struct {
			MasterKey string `json:"master_key"`
		}
		if err := c.call("POST", "/v1/sys/init", map[string]string{"username": *user, "password": password}, &out); err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, out.MasterKey)
		return err

	case "unseal":
		key, err := readLine(in)
		if err != nil {
			return err
		}
		return c.call("POST", "/v1/sys/unseal", map[string]string{"master_key": key}, nil)

	case "apply":
		if err := needUser(); err != nil {
			return err
		}
		password, err := readLine(in)
		if err != nil {
			return err
		}
		var list json.RawMessage
		if err := json.NewDecoder(in).Decode(&list); err != nil {
			return errors.New("client list on stdin is not valid JSON")
		}
		if err := c.login(*user, password); err != nil {
			return err
		}
		var report map[string]any
		if err := c.call("POST", "/v1/admin/apply", list, &report); err != nil {
			return err
		}
		for _, key := range []string{"created_clients", "updated_clients", "created_secrets", "missing_static", "clients_not_in_list"} {
			items, _ := report[key].([]any)
			names := make([]string, 0, len(items))
			for _, item := range items {
				names = append(names, fmt.Sprint(item))
			}
			if _, err := fmt.Fprintf(stdout, "%s: %s\n", key, strings.Join(names, " ")); err != nil {
				return err
			}
		}
		return nil

	case "enroll":
		if err := needUser(); err != nil {
			return err
		}
		names := fs.Args()
		if len(names) == 0 {
			return errors.New("name at least one client")
		}
		password, err := readLine(in)
		if err != nil {
			return err
		}
		if err := c.login(*user, password); err != nil {
			return err
		}
		var clients []struct {
			ID        string     `json:"id"`
			Name      string     `json:"name"`
			RevokedAt *time.Time `json:"revoked_at"`
		}
		if err := c.call("GET", "/v1/admin/clients", nil, &clients); err != nil {
			return err
		}
		ids := map[string]string{}
		for _, cl := range clients {
			if cl.RevokedAt == nil {
				ids[cl.Name] = cl.ID
			}
		}
		// Check all names first: no codes at all when one is wrong
		for _, name := range names {
			if ids[name] == "" {
				return fmt.Errorf("unknown client %s (apply the client list first)", name)
			}
		}
		slices.Sort(names)
		for _, name := range slices.Compact(names) {
			var out struct {
				Code string `json:"code"`
			}
			if err := c.call("POST", "/v1/admin/clients/"+ids[name]+"/enroll", nil, &out); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(stdout, "%s %s\n", name, out.Code); err != nil {
				return err
			}
		}
		return nil
	}
	return errors.New("unknown admin command " + args[0])
}
