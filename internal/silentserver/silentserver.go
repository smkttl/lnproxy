package silentserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"lnproxy/internal/auth"
	"lnproxy/internal/config"
	"lnproxy/internal/node"
	"lnproxy/internal/transport"
)

// LoadConfig loads the initialized server-exit bundle from dataDir. It forces
// the role and bundle paths so a copied bundle does not depend on the source
// machine or Windows user profile.
func LoadConfig(dataDir string) (config.Node, error) {
	if dataDir == "" {
		return config.Node{}, fmt.Errorf("data directory is required")
	}
	configPath := filepath.Join(dataDir, "node.json")
	cfg, err := config.LoadNode(configPath)
	if err != nil {
		return config.Node{}, fmt.Errorf("load %s: %w", configPath, err)
	}
	cfg.Role = config.RoleServerExit
	cfg.Console = false
	cfg.DataDirectory = dataDir
	cfg.CertificateFile = filepath.Join(dataDir, "server.crt")
	cfg.KeyFile = filepath.Join(dataDir, "server.key")
	cfg.VerifierFile = filepath.Join(dataDir, "passphrase.json")
	if err := cfg.Validate(); err != nil {
		return config.Node{}, err
	}

	required := []struct {
		name string
		path string
	}{
		{name: "passphrase verifier", path: cfg.VerifierFile},
		{name: "TLS certificate", path: cfg.CertificateFile},
		{name: "TLS private key", path: cfg.KeyFile},
	}
	for _, file := range required {
		info, err := os.Stat(file.path)
		if err != nil {
			return config.Node{}, fmt.Errorf("%s %s is required: %w", file.name, file.path, err)
		}
		if info.IsDir() {
			return config.Node{}, fmt.Errorf("%s %s is a directory", file.name, file.path)
		}
	}
	return cfg, nil
}

// Run starts the initialized server-exit node. LoadConfig performs all bundle
// validation before any listener is opened.
func Run(ctx context.Context, dataDir string, logger *slog.Logger) error {
	cfg, err := LoadConfig(dataDir)
	if err != nil {
		return err
	}
	verifier, err := auth.LoadVerifier(cfg.VerifierFile)
	if err != nil {
		return fmt.Errorf("load passphrase verifier: %w", err)
	}
	certificate, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	tlsConfig := transport.BaseTLSConfig(&certificate)
	return node.NewServer(cfg, verifier, tlsConfig, logger).Run(ctx)
}
