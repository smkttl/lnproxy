package node

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"

	"lnproxy/internal/config"
	"lnproxy/internal/transport"
)

func TestExitTrustFailureIsPermanent(t *testing.T) {
	config := transport.ClientTLSConfig("", untrustedExitStore{}, "server.example")
	err := config.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Raw: []byte("server certificate")}},
	})
	if !transport.IsTrustError(err) {
		t.Fatalf("VerifyConnection() error = %v, want trust error", err)
	}
}

func TestExitExplicitFingerprintOverridesTrustStore(t *testing.T) {
	store := &recordingTrust{fingerprint: "AA:BB"}
	exit := NewExit(config.Node{ServerFingerprint: "CC:DD"}, "passphrase", nil, nil)
	exit.UseTrust(store)

	expected, trust := exit.trustConfig("server.example")
	if expected != "CC:DD" {
		t.Fatalf("expected fingerprint = %q, want explicit pin", expected)
	}
	if trust != nil {
		t.Fatal("trust store was used with an explicit fingerprint")
	}
	if store.calls != 0 {
		t.Fatalf("trust store calls = %d, want 0", store.calls)
	}
}

type recordingTrust struct {
	fingerprint string
	calls       int
}

func (t *recordingTrust) Get(string) string {
	t.calls++
	return t.fingerprint
}

func (*recordingTrust) Check(string, string) error {
	return nil
}

func (*recordingTrust) Save(string, string) error {
	return nil
}

type untrustedExitStore struct{}

func (untrustedExitStore) Get(string) string {
	return ""
}

func (untrustedExitStore) Check(string, string) error {
	return nil
}

func (untrustedExitStore) Save(string, string) error {
	return errors.New("server certificate fingerprint was not accepted")
}
