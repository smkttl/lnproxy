package initnode

import (
	"fmt"
	"os"
	"path/filepath"

	"lnproxy/internal/auth"
	"lnproxy/internal/config"
)

// Initialize creates an initialized node bundle and refuses to overwrite an
// existing verifier.
func Initialize(cfg config.Node, configPath string) error {
	if err := os.MkdirAll(cfg.DataDirectory, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(cfg.VerifierFile); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite", cfg.VerifierFile)
	}
	passphrase, err := auth.PromptPassphrase("Passphrase: ", true)
	if err != nil {
		return err
	}
	verifier, err := auth.NewVerifier(passphrase)
	if err != nil {
		return err
	}
	if err := verifier.Save(cfg.VerifierFile); err != nil {
		return err
	}
	if cfg.Role != config.RoleExit {
		if err := config.GenerateCertificate(cfg.CertificateFile, cfg.KeyFile, ""); err != nil {
			return err
		}
	}
	path := configPath
	if path == "" {
		path = filepath.Join(cfg.DataDirectory, "node.json")
	}
	if err := config.SaveNode(path, cfg); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "initialized %s\nconfiguration: %s\n", cfg.Role, path)
	return nil
}
