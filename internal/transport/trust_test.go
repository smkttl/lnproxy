package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestClientTLSConfigMarksFingerprintMismatchAsTrustError(t *testing.T) {
	peer := &x509.Certificate{Raw: []byte("server certificate")}
	config := ClientTLSConfig("AA:BB", nil, "server.example")
	err := config.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}})
	if !IsTrustError(err) {
		t.Fatalf("error = %v, want trust error", err)
	}
}

func TestClientTLSConfigMarksMissingTrustAsTrustError(t *testing.T) {
	peer := &x509.Certificate{Raw: []byte("server certificate")}
	config := ClientTLSConfig("", nil, "server.example")
	err := config.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}})
	if !IsTrustError(err) {
		t.Fatalf("error = %v, want trust error", err)
	}
}

func TestClientTLSConfigMarksStoreRejectionAsTrustError(t *testing.T) {
	peer := &x509.Certificate{Raw: []byte("server certificate")}
	config := ClientTLSConfig("", rejectingTrust{}, "server.example")
	err := config.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}})
	if !IsTrustError(err) {
		t.Fatalf("error = %v, want trust error", err)
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("error = %v, want original trust error", err)
	}
}

func TestIsTrustErrorSeesWrappedError(t *testing.T) {
	err := fmt.Errorf("outer: %w", &TrustError{Err: errors.New("trust failed")})
	if !IsTrustError(err) {
		t.Fatalf("IsTrustError(%v) = false, want true", err)
	}
}

type rejectingTrust struct{}

func (rejectingTrust) Check(string, string) error {
	return nil
}

func (rejectingTrust) Save(string, string) error {
	return errors.New("rejected by test")
}
