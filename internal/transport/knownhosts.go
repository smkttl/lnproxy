package transport

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type KnownHosts struct {
	mu      sync.Mutex
	path    string
	entries map[string]string
	confirm func(host, fingerprint string) (bool, error)
}

func LoadKnownHosts(path string) (*KnownHosts, error) {
	known := &KnownHosts{path: path, entries: make(map[string]string)}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return known, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &known.entries); err != nil {
		return nil, fmt.Errorf("parse known hosts: %w", err)
	}
	return known, nil
}

func (k *KnownHosts) Get(host string) string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.entries[host]
}

func (k *KnownHosts) SetConfirmer(confirm func(host, fingerprint string) (bool, error)) {
	k.mu.Lock()
	k.confirm = confirm
	k.mu.Unlock()
}

func (k *KnownHosts) SaveUnconfirmed(host, fingerprint string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.entries[host] = NormalizeFingerprint(fingerprint)
	data, err := json.MarshalIndent(k.entries, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(k.path), 0o700); err != nil {
		return err
	}
	temp := k.path + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temp, k.path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

func (k *KnownHosts) Save(host, fingerprint string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if existing := k.entries[host]; existing != "" && !EqualFingerprint(existing, fingerprint) {
		return fmt.Errorf("refusing to replace fingerprint for %s", host)
	}
	if k.entries[host] == "" {
		if k.confirm == nil {
			return fmt.Errorf("server %s is not trusted and no fingerprint confirmation is available", host)
		}
		confirmed, err := k.confirm(host, NormalizeFingerprint(fingerprint))
		if err != nil {
			return err
		}
		if !confirmed {
			return fmt.Errorf("server certificate fingerprint for %s was not accepted", host)
		}
	}
	k.entries[host] = NormalizeFingerprint(fingerprint)
	data, err := json.MarshalIndent(k.entries, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(k.path), 0o700); err != nil {
		return err
	}
	temp := k.path + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temp, k.path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

func (k *KnownHosts) Check(host, fingerprint string) error {
	expected := k.Get(host)
	if expected == "" {
		return nil
	}
	if !EqualFingerprint(expected, fingerprint) {
		return fmt.Errorf("server certificate fingerprint changed for %s: expected %s, got %s", host, expected, fingerprint)
	}
	return nil
}
