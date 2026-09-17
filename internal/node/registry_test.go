package node

import (
	"testing"
	"time"

	"lnproxy/internal/auth"
	"lnproxy/internal/config"
	"lnproxy/internal/protocol"
)

func TestRegistrySelectionAndExpiry(t *testing.T) {
	t.Parallel()
	registry := NewRegistry(20 * time.Millisecond)
	registry.Add(protocol.ExitInfo{ID: "slow", Capacity: 2, LatencyMS: 200}, "healthy")
	registry.Add(protocol.ExitInfo{ID: "fast", Capacity: 2, LatencyMS: 10}, "healthy")
	registry.AddPersistent(protocol.ExitInfo{ID: "direct", Capacity: 1, LatencyMS: 500}, "healthy")
	selected, err := registry.Select("auto", false)
	if err != nil {
		t.Fatal(err)
	}
	if selected.ID != "fast" {
		t.Fatalf("selected %s, want fast", selected.ID)
	}
	if _, err := registry.Select("missing", false); err != ErrExitUnavailable {
		t.Fatalf("got %v, want unavailable", err)
	}
	time.Sleep(30 * time.Millisecond)
	exits := registry.Expire()
	if len(exits) != 1 || exits[0].ID != "direct" {
		t.Fatalf("got %#v, want only persistent direct exit", exits)
	}
}

func TestServerDirectExitIsPersistent(t *testing.T) {
	t.Parallel()
	cfg, err := config.DefaultNode(config.RoleServerExit)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(cfg, auth.Verifier{}, nil, nil)
	if _, ok := server.registry.Get("direct"); !ok {
		t.Fatal("direct exit was not registered")
	}
	server.registry.staleFor = time.Millisecond
	time.Sleep(5 * time.Millisecond)
	exits := server.registry.Expire()
	if len(exits) != 1 || exits[0].ID != "direct" {
		t.Fatalf("got %#v, want direct exit to survive expiry", exits)
	}
}
