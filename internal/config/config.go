package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	RoleServer      = "server"
	RoleExit        = "exit"
	RoleServerExit  = "server-exit"
	DefaultListen   = ":443"
	DefaultIdle     = 5 * time.Minute
	DefaultCapacity = 128
)

type Node struct {
	Role              string        `json:"role"`
	ListenAddress     string        `json:"listen_address"`
	DataDirectory     string        `json:"data_directory"`
	CertificateFile   string        `json:"certificate_file"`
	KeyFile           string        `json:"key_file"`
	VerifierFile      string        `json:"verifier_file"`
	ServerAddress     string        `json:"server_address,omitempty"`
	ServerFingerprint string        `json:"server_fingerprint,omitempty"`
	PassphraseSource  string        `json:"passphrase_source"`
	ConnectionLimit   int           `json:"connection_limit"`
	IdleTimeout       time.Duration `json:"idle_timeout"`
	ExitName          string        `json:"exit_name,omitempty"`
	ExitID            string        `json:"exit_id,omitempty"`
	Capacity          int           `json:"capacity,omitempty"`
	Console           bool          `json:"console,omitempty"`
}

func DefaultDataDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "lnproxy"), nil
}

func DefaultNode(role string) (Node, error) {
	dataDir, err := DefaultDataDir()
	if err != nil {
		return Node{}, err
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "node"
	}
	node := Node{
		Role:             role,
		ListenAddress:    DefaultListen,
		DataDirectory:    dataDir,
		CertificateFile:  filepath.Join(dataDir, "server.crt"),
		KeyFile:          filepath.Join(dataDir, "server.key"),
		VerifierFile:     filepath.Join(dataDir, "passphrase.json"),
		PassphraseSource: "prompt",
		ConnectionLimit:  256,
		IdleTimeout:      DefaultIdle,
		ExitName:         hostname,
		Capacity:         DefaultCapacity,
	}
	return node, nil
}

func (n Node) Validate() error {
	switch n.Role {
	case RoleServer, RoleExit, RoleServerExit:
	default:
		return fmt.Errorf("unsupported node role %q", n.Role)
	}
	if n.DataDirectory == "" {
		return errors.New("data directory is required")
	}
	if n.ConnectionLimit <= 0 {
		return errors.New("connection limit must be positive")
	}
	if n.IdleTimeout <= 0 {
		return errors.New("idle timeout must be positive")
	}
	if n.Role == RoleExit || n.Role == RoleServerExit {
		if n.Role == RoleExit && n.ServerAddress == "" {
			return errors.New("exit mode requires server_address")
		}
		if n.Capacity <= 0 {
			return errors.New("capacity must be positive")
		}
	}
	if n.Role == RoleServer || n.Role == RoleServerExit {
		if n.ListenAddress == "" {
			return errors.New("listen address is required")
		}
	}
	return nil
}

func (n Node) FillPaths() Node {
	if n.DataDirectory == "" {
		n.DataDirectory, _ = DefaultDataDir()
	}
	if err := os.MkdirAll(n.DataDirectory, 0o700); err == nil {
		// Best effort: callers that need to report a creation error will do so
		// when writing their first file.
	}
	if n.CertificateFile == "" {
		n.CertificateFile = filepath.Join(n.DataDirectory, "server.crt")
	}
	if n.KeyFile == "" {
		n.KeyFile = filepath.Join(n.DataDirectory, "server.key")
	}
	if n.VerifierFile == "" {
		n.VerifierFile = filepath.Join(n.DataDirectory, "passphrase.json")
	}
	if n.ListenAddress == "" {
		n.ListenAddress = DefaultListen
	}
	if n.ConnectionLimit == 0 {
		n.ConnectionLimit = 256
	}
	if n.IdleTimeout == 0 {
		n.IdleTimeout = DefaultIdle
	}
	if n.Capacity == 0 {
		n.Capacity = DefaultCapacity
	}
	if n.ExitID == "" {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "exit"
		}
		n.ExitID = hostname
	}
	if n.PassphraseSource == "" {
		n.PassphraseSource = "prompt"
	}
	return n
}

func LoadNode(path string) (Node, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Node{}, err
	}
	var node Node
	if err := json.Unmarshal(data, &node); err != nil {
		return Node{}, fmt.Errorf("parse node config: %w", err)
	}
	node = node.FillPaths()
	return node, node.Validate()
}

func SaveNode(path string, node Node) error {
	node = node.FillPaths()
	data, err := json.MarshalIndent(node, "", "  ")
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

func GenerateCertificate(certPath, keyPath, hostname string) error {
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return err
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "lnproxy",
			Organization: []string{"lnproxy"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeFile(certPath, certPEM, 0o644); err != nil {
		return err
	}
	return writeFile(keyPath, keyPEM, 0o600)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	temp := path + ".tmp"
	if err := os.WriteFile(temp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(temp, mode); err != nil && runtime.GOOS != "windows" {
		_ = os.Remove(temp)
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

func NormalizeServerAddress(address string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", errors.New("server address is required")
	}
	if _, _, err := net.SplitHostPort(address); err == nil {
		return address, nil
	}
	if strings.Contains(address, ":") && !strings.HasPrefix(address, "[") {
		if ip := net.ParseIP(address); ip != nil {
			return net.JoinHostPort(address, "443"), nil
		}
	}
	if strings.Count(address, ":") == 0 {
		return net.JoinHostPort(address, "443"), nil
	}
	return "", fmt.Errorf("invalid server address %q", address)
}
