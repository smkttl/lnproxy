package systemproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Endpoint struct {
	HTTP  string `json:"http"`
	HTTPS string `json:"https,omitempty"`
	SOCKS string `json:"socks,omitempty"`
}

type Snapshot struct {
	Version int             `json:"version"`
	Values  json.RawMessage `json:"values"`
}

type SystemProxy interface {
	Snapshot(context.Context) (Snapshot, error)
	Apply(context.Context, Endpoint) error
	Restore(context.Context, Snapshot) error
}

type StateMatcher interface {
	Matches(context.Context, Snapshot, Endpoint) (bool, error)
}

var ErrUnsupported = errors.New("system proxy settings are unsupported in this environment")

type Journal struct {
	Version int       `json:"version"`
	PID     int       `json:"pid"`
	Applied Endpoint  `json:"applied"`
	Before  Snapshot  `json:"before"`
	Time    time.Time `json:"timestamp"`
}

func JournalPath(dataDir string) string {
	return filepath.Join(dataDir, "system-proxy-journal.json")
}

func WriteJournal(path string, journal Journal) error {
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp := path + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

func ReadJournal(path string) (Journal, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Journal{}, err
	}
	var journal Journal
	if err := json.Unmarshal(data, &journal); err != nil {
		return Journal{}, fmt.Errorf("parse proxy journal: %w", err)
	}
	if journal.Version != 1 {
		return Journal{}, fmt.Errorf("unsupported journal version %d", journal.Version)
	}
	return journal, nil
}

func RemoveJournal(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
