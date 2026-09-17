package auth

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestChallengeAuthentication(t *testing.T) {
	t.Parallel()
	verifier, err := NewVerifier("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	serverResult := make(chan error, 1)
	go func() {
		_, err := ServerHandshake(server, verifier, RoleClient)
		serverResult <- err
	}()
	if err := ClientHandshakePassword(client, "correct horse battery staple", RoleClient); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}

func TestChallengeRejectsWrongPassword(t *testing.T) {
	t.Parallel()
	verifier, err := NewVerifier("correct")
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	serverResult := make(chan error, 1)
	go func() {
		_, err := ServerHandshake(server, verifier, RoleClient)
		serverResult <- err
	}()
	if err := ClientHandshakePassword(client, "wrong", RoleClient); err == nil {
		t.Fatal("expected client authentication failure")
	}
	if err := <-serverResult; err == nil {
		t.Fatal("expected server authentication failure")
	}
}

func TestRateLimiter(t *testing.T) {
	t.Parallel()
	limiter := NewRateLimiter(2, time.Minute, time.Minute)
	if err := limiter.Allowed("peer"); err != nil {
		t.Fatal(err)
	}
	limiter.Fail("peer")
	if err := limiter.Allowed("peer"); err != nil {
		t.Fatal(err)
	}
	limiter.Fail("peer")
	if err := limiter.Allowed("peer"); err != ErrRateLimited {
		t.Fatalf("got %v, want rate limit", err)
	}
}

func TestVerifierRoundTrip(t *testing.T) {
	t.Parallel()
	verifier, err := NewVerifier("secret")
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/verifier.json"
	if err := verifier.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadVerifier(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Verify("secret") || loaded.Verify("wrong") {
		t.Fatal("loaded verifier mismatch")
	}
	if bytes.Equal(loaded.Hash, []byte("secret")) {
		t.Fatal("stored passphrase was not hashed")
	}
}
