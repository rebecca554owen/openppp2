package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigUsesSafeDefaultsAndGeneratesAuthSecret(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "guardian.json"))
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if cfg.Listen != "127.0.0.1:18080" {
		t.Fatalf("Listen = %q, want loopback default", cfg.Listen)
	}
	if !cfg.Auth.Enabled {
		t.Fatal("Auth.Enabled = false, want true")
	}
	if cfg.Auth.JWTSecret == "" {
		t.Fatal("JWTSecret is empty, want generated secret")
	}
	if !cfg.GeneratedJWTSecret {
		t.Fatal("GeneratedJWTSecret = false, want true")
	}
}

func TestLoadConfigGeneratesSecretForEmptyEnabledAuth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardian.json")
	data, err := json.Marshal(GuardianConfig{Auth: AuthConfig{Enabled: true}})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if cfg.Auth.JWTSecret == "" {
		t.Fatal("JWTSecret is empty, want generated secret")
	}
	if !cfg.GeneratedJWTSecret {
		t.Fatal("GeneratedJWTSecret = false, want true")
	}
}

func TestSaveConfigFilePersistsSecretWithoutDroppingInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardian.json")
	cfg := DefaultConfig()
	cfg.Auth.JWTSecret = "generated-secret"
	cfg.GeneratedJWTSecret = true
	cfg.Instances = []InstanceConfig{{Name: "disabled", Enabled: false, Binary: "/bin/ppp"}}

	if err := SaveConfigFile(path, cfg); err != nil {
		t.Fatalf("SaveConfigFile() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var saved GuardianConfig
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if saved.Auth.JWTSecret != "generated-secret" {
		t.Fatalf("JWTSecret = %q, want generated-secret", saved.Auth.JWTSecret)
	}
	if saved.GeneratedJWTSecret {
		t.Fatal("GeneratedJWTSecret should not be serialized")
	}
	if len(saved.Instances) != 1 || saved.Instances[0].Name != "disabled" || saved.Instances[0].Enabled {
		t.Fatalf("Instances = %+v, want disabled instance preserved", saved.Instances)
	}
}

func TestSaveConfigFileRestrictsExistingFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardian.json")
	if err := os.WriteFile(path, []byte(`{"auth":{"enabled":true}}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg := DefaultConfig()
	cfg.Auth.JWTSecret = "generated-secret"
	if err := SaveConfigFile(path, cfg); err != nil {
		t.Fatalf("SaveConfigFile() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
}
