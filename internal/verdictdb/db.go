package verdictdb

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/attach-dev/attach-open-score/pkg/schema"
)

type DB struct {
	path string
	mu   sync.Mutex
}

type fileData struct {
	SchemaVersion string  `json:"schema_version"`
	Entries       []Entry `json:"entries"`
}

type Entry struct {
	Key     Key            `json:"key"`
	Verdict schema.Verdict `json:"verdict"`
}

type Key struct {
	Ecosystem     string `json:"ecosystem"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	PolicyProfile string `json:"policy_profile"`
}

const schemaVersion = "attach-open-score-cache/v0"

// maxEntries bounds the on-disk cache so an attacker submitting an unbounded
// stream of distinct package coordinates cannot exhaust disk or degrade the
// O(n) rewrite path. Oldest entries are evicted first (FIFO). It is a var only
// so tests can exercise eviction with a small bound.
var maxEntries = 50000

func DefaultPath() string {
	if override := strings.TrimSpace(os.Getenv("ATTACH_OPEN_SCORE_DB_PATH")); override != "" {
		return override
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return filepath.Join(".attach-open-score", "scores.json")
	}
	return filepath.Join(home, ".attach-open-score", "scores.json")
}

func New(path string) *DB {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath()
	}
	return &DB{path: path}
}

func NormalizeKey(ecosystem, name, version, policyProfile string) Key {
	return Key{
		Ecosystem:     strings.ToLower(strings.TrimSpace(ecosystem)),
		Name:          strings.ToLower(strings.TrimSpace(name)),
		Version:       strings.TrimSpace(version),
		PolicyProfile: strings.TrimSpace(policyProfile),
	}
}

func (db *DB) Get(key Key) (schema.Verdict, bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	data, err := db.load()
	if err != nil {
		return schema.Verdict{}, false, err
	}
	for _, entry := range data.Entries {
		if entry.Key == key {
			return entry.Verdict, true, nil
		}
	}
	return schema.Verdict{}, false, nil
}

func (db *DB) Put(key Key, verdict schema.Verdict) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	data, err := db.load()
	if err != nil {
		return err
	}
	replaced := false
	for i := range data.Entries {
		if data.Entries[i].Key == key {
			data.Entries[i].Verdict = verdict
			replaced = true
			break
		}
	}
	if !replaced {
		data.Entries = append(data.Entries, Entry{Key: key, Verdict: verdict})
		if len(data.Entries) > maxEntries {
			data.Entries = data.Entries[len(data.Entries)-maxEntries:]
		}
	}
	return db.save(data)
}

func (db *DB) load() (fileData, error) {
	data := fileData{SchemaVersion: schemaVersion}
	raw, err := os.ReadFile(db.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return data, nil
		}
		return fileData{}, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return data, nil
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return fileData{}, fmt.Errorf("read score database %s: %w", db.path, err)
	}
	if data.SchemaVersion == "" {
		data.SchemaVersion = schemaVersion
	}
	if data.SchemaVersion != schemaVersion {
		return fileData{}, fmt.Errorf("unsupported score database schema %q", data.SchemaVersion)
	}
	return data, nil
}

func (db *DB) save(data fileData) error {
	data.SchemaVersion = schemaVersion
	if err := os.MkdirAll(filepath.Dir(db.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := db.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, db.path)
}
