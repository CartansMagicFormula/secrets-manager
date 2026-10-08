// Package audit writes a tamper-evident log: every entry carries the SHA-256
// of the previous entry, so a removed or edited line breaks the chain.
// Entries never contain secret values.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Entry of the log.
type Entry struct {
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Path    string    `json:"path,omitempty"`
	Version int       `json:"version,omitempty"`
	OK      bool      `json:"ok"`
	Detail  string    `json:"detail,omitempty"`
	Prev    string    `json:"prev"`
	Hash    string    `json:"hash"`
}

func digest(e Entry) string {
	e.Hash = ""
	body, _ := json.Marshal(e)
	sum := sha256.Sum256(append([]byte(e.Prev), body...))
	return hex.EncodeToString(sum[:])
}

// Log appends entries to a file.
type Log struct {
	mu   sync.Mutex
	path string
	last string
	now  func() time.Time
}

// Open the log and remember the hash of its last entry.
func Open(path string) (*Log, error) {
	l := &Log{path: path, last: "genesis", now: time.Now}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err == nil {
			l.last = e.Hash
		}
	}
	return l, scanner.Err()
}

// Write appends one entry.
func (l *Log) Write(actor, action, path string, version int, ok bool, detail string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Entry{Time: l.now().UTC(), Actor: actor, Action: action, Path: path, Version: version, OK: ok, Detail: detail, Prev: l.last}
	e.Hash = digest(e)
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	l.last = e.Hash
	return nil
}

// Head is the hash of the last entry (to ship elsewhere for outside verification).
func (l *Log) Head() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.last
}

// Tail returns the last n entries (newest first).
func (l *Log) Tail(n int) ([]Entry, error) {
	entries, err := l.read()
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, n)
	for i := len(entries) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, entries[i])
	}
	return out, nil
}

func (l *Log) read() ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	line := 0
	for scanner.Scan() {
		line++
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("line %d: unreadable", line)
		}
		entries = append(entries, e)
	}
	return entries, scanner.Err()
}

// Verify recomputes the chain; returns the number of entries or the first broken line.
func (l *Log) Verify() (int, error) {
	entries, err := l.read()
	if err != nil {
		return 0, err
	}
	prev := "genesis"
	for i, e := range entries {
		if e.Prev != prev || digest(e) != e.Hash {
			return i, fmt.Errorf("chain broken at entry %d", i+1)
		}
		prev = e.Hash
	}
	return len(entries), nil
}
