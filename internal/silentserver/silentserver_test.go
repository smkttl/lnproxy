package silentserver

import (
	"os"
	"path/filepath"
	"testing"

	"lnproxy/internal/config"
)

func TestLoadConfigRebasesBundle(t *testing.T) {
	dataDir := t.TempDir()
	cfg, err := config.DefaultNode(config.RoleServerExit)
	if err != nil {
		t.Fatalf("DefaultNode() error = %v", err)
	}
	cfg.DataDirectory = `C:\Users\old-user\AppData\Roaming\lnproxy`
	cfg.CertificateFile = `C:\Users\old-user\AppData\Roaming\lnproxy\server.crt`
	cfg.KeyFile = `C:\Users\old-user\AppData\Roaming\lnproxy\server.key`
	cfg.VerifierFile = `C:\Users\old-user\AppData\Roaming\lnproxy\passphrase.json`
	cfg.Console = true
	if err := config.SaveNode(filepath.Join(dataDir, "node.json"), cfg); err != nil {
		t.Fatalf("SaveNode() error = %v", err)
	}
	writeBundleFiles(t, dataDir)

	loaded, err := LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if loaded.Role != config.RoleServerExit {
		t.Fatalf("Role = %q, want %q", loaded.Role, config.RoleServerExit)
	}
	if loaded.Console {
		t.Fatal("Console = true, want false")
	}
	wantPaths := []string{
		dataDir,
		filepath.Join(dataDir, "server.crt"),
		filepath.Join(dataDir, "server.key"),
		filepath.Join(dataDir, "passphrase.json"),
	}
	gotPaths := []string{
		loaded.DataDirectory,
		loaded.CertificateFile,
		loaded.KeyFile,
		loaded.VerifierFile,
	}
	for i := range wantPaths {
		if gotPaths[i] != wantPaths[i] {
			t.Fatalf("path %d = %q, want %q", i, gotPaths[i], wantPaths[i])
		}
	}
}

func TestLoadConfigRequiresBundleFiles(t *testing.T) {
	dataDir := t.TempDir()
	cfg, err := config.DefaultNode(config.RoleServerExit)
	if err != nil {
		t.Fatalf("DefaultNode() error = %v", err)
	}
	if err := config.SaveNode(filepath.Join(dataDir, "node.json"), cfg); err != nil {
		t.Fatalf("SaveNode() error = %v", err)
	}
	if _, err := LoadConfig(dataDir); err == nil {
		t.Fatal("LoadConfig() error = nil, want missing bundle error")
	}
}

func TestLoadConfigRejectsMalformedBundle(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "node.json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := LoadConfig(dataDir); err == nil {
		t.Fatal("LoadConfig() error = nil, want parse error")
	}
}

func TestLoadConfigForcesServerExitRole(t *testing.T) {
	dataDir := t.TempDir()
	cfg, err := config.DefaultNode(config.RoleServer)
	if err != nil {
		t.Fatalf("DefaultNode() error = %v", err)
	}
	if err := config.SaveNode(filepath.Join(dataDir, "node.json"), cfg); err != nil {
		t.Fatalf("SaveNode() error = %v", err)
	}
	writeBundleFiles(t, dataDir)

	loaded, err := LoadConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if loaded.Role != config.RoleServerExit {
		t.Fatalf("Role = %q, want %q", loaded.Role, config.RoleServerExit)
	}
}

func writeBundleFiles(t *testing.T, dataDir string) {
	t.Helper()
	for _, name := range []string{"passphrase.json", "server.crt", "server.key"} {
		if err := os.WriteFile(filepath.Join(dataDir, name), []byte("test"), 0o600); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", name, err)
		}
	}
}
