package main

import (
	"reflect"
	"testing"

	"lnproxy/internal/config"
)

func TestParseInvocationExplicitRole(t *testing.T) {
	role, args, err := parseInvocation([]string{"server-exit", "--init"})
	if err != nil {
		t.Fatalf("parseInvocation() error = %v", err)
	}
	if role != config.RoleServerExit {
		t.Fatalf("role = %q, want %q", role, config.RoleServerExit)
	}
	if want := []string{"--init"}; !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
}

func TestParseInvocationRejectsMissingRole(t *testing.T) {
	if _, _, err := parseInvocation(nil); err == nil {
		t.Fatal("parseInvocation() error = nil, want usage error")
	}
	if _, _, err := parseInvocation([]string{"--init"}); err == nil {
		t.Fatal("parseInvocation(--init) error = nil, want role error")
	}
}

func TestInitializationUsesConfigAsOutputPath(t *testing.T) {
	role, args, err := parseInvocation([]string{"server-exit", "--init", "--config", "new-node.json"})
	if err != nil {
		t.Fatalf("parseInvocation() error = %v", err)
	}
	opts, err := parseOptions(role, args)
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if !opts.initMode {
		t.Fatal("initMode = false, want true")
	}
	if opts.configPath != "new-node.json" {
		t.Fatalf("configPath = %q, want %q", opts.configPath, "new-node.json")
	}
}
