package main

import (
	"testing"

	"lnproxy/internal/config"
)

func TestParseOptionsForEachRole(t *testing.T) {
	for _, role := range []string{config.RoleServer, config.RoleExit, config.RoleServerExit} {
		gotRole, opts, err := parseOptions([]string{role, "--config", "node.json", "--data-dir", "data"})
		if err != nil {
			t.Fatalf("parseOptions(%q) error = %v", role, err)
		}
		if gotRole != role {
			t.Fatalf("role = %q, want %q", gotRole, role)
		}
		if opts.configPath != "node.json" || opts.dataDir != "data" {
			t.Fatalf("options = %#v, want config and data paths", opts)
		}
	}
}

func TestParseOptionsRequiresRole(t *testing.T) {
	if _, _, err := parseOptions(nil); err == nil {
		t.Fatal("parseOptions() error = nil, want usage error")
	}
}

func TestParseOptionsRejectsUnknownRole(t *testing.T) {
	if _, _, err := parseOptions([]string{"unknown"}); err == nil {
		t.Fatal("parseOptions() error = nil, want role error")
	}
}
