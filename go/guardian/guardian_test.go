package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"ppp/guardian/instance"
)

func TestGuardianSaveConfigWritesSecretConfigOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardian.json")
	guardian := &Guardian{
		cfg: &GuardianConfig{
			Listen: "127.0.0.1:18080",
			Auth: AuthConfig{
				Enabled:   true,
				JWTSecret: "generated-secret",
			},
		},
		configPath: path,
		instances:  instance.NewManager(),
	}

	if err := guardian.SaveConfig(); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
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
}

func TestGuardianUpdateAuthConfigPersistsPasswordOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardian.json")
	guardian := &Guardian{
		cfg: &GuardianConfig{
			Listen: "127.0.0.1:18080",
			Auth: AuthConfig{
				Enabled:          true,
				JWTSecret:        "old-secret",
				TokenExpiryHours: 24,
			},
		},
		configPath: path,
		instances:  instance.NewManager(),
	}

	if err := guardian.UpdateAuthConfig(true, "new-secret"); err != nil {
		t.Fatalf("UpdateAuthConfig() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var saved GuardianConfig
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !saved.Auth.Enabled || saved.Auth.JWTSecret != "new-secret" {
		t.Fatalf("saved auth = %+v, want enabled with new secret", saved.Auth)
	}
	if saved.Auth.TokenExpiryHours != 24 {
		t.Fatalf("TokenExpiryHours = %d, want 24", saved.Auth.TokenExpiryHours)
	}
}
