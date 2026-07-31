//go:build linux

package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type SystemdConfig struct {
	ServiceName string
	Description string
	ExecStart   string
	WorkingDir  string
	User        string
	Restart     string
	RestartSec  int
	WantedBy    string
}

func InstallSystemd(cfg SystemdConfig) error {
	if os.Geteuid() != 0 {
		return errors.New("systemd installation requires root privileges")
	}
	if cfg.ServiceName == "" {
		return errors.New("service name is required")
	}
	if cfg.Description == "" {
		return errors.New("service description is required")
	}
	if cfg.ExecStart == "" {
		return errors.New("exec start is required")
	}
	if cfg.WorkingDir == "" {
		return errors.New("working directory is required")
	}
	applySystemdDefaults(&cfg)

	unitPath := systemdUnitPath(cfg.ServiceName)
	if err := os.WriteFile(unitPath, []byte(renderUnitFile(cfg)), 0o644); err != nil {
		return fmt.Errorf("write systemd unit: %w", err)
	}
	if err := runSystemctl("daemon-reload"); err != nil {
		return err
	}
	if err := runSystemctl("enable", cfg.ServiceName); err != nil {
		return err
	}
	return nil
}

func UninstallSystemd(serviceName string) error {
	if os.Geteuid() != 0 {
		return errors.New("systemd uninstallation requires root privileges")
	}
	if serviceName == "" {
		return errors.New("service name is required")
	}

	_ = runSystemctl("stop", serviceName)
	if err := runSystemctl("disable", serviceName); err != nil {
		return err
	}
	if err := os.Remove(systemdUnitPath(serviceName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove systemd unit: %w", err)
	}
	if err := runSystemctl("daemon-reload"); err != nil {
		return err
	}
	return nil
}

func SystemdStatus(serviceName string) (string, error) {
	if serviceName == "" {
		return "unknown", errors.New("service name is required")
	}
	cmd := exec.Command("systemctl", "is-active", serviceName)
	out, err := cmd.Output()
	if err != nil {
		if len(out) > 0 {
			return strings.TrimSpace(string(out)), nil
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return strings.TrimSpace(string(exitErr.Stderr)), nil
		}
		return "unknown", fmt.Errorf("systemctl is-active %s: %w", serviceName, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func applySystemdDefaults(cfg *SystemdConfig) {
	if cfg.User == "" {
		cfg.User = "root"
	}
	if cfg.Restart == "" {
		cfg.Restart = "always"
	}
	if cfg.RestartSec <= 0 {
		cfg.RestartSec = 10
	}
	if cfg.WantedBy == "" {
		cfg.WantedBy = "multi-user.target"
	}
}

func renderUnitFile(cfg SystemdConfig) string {
	return fmt.Sprintf(`[Unit]
Description=%s
After=network.target

[Service]
Type=simple
ExecStart=%s
WorkingDirectory=%s
User=%s
Restart=%s
RestartSec=%d
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=%s
`, cfg.Description, cfg.ExecStart, cfg.WorkingDir, cfg.User, cfg.Restart, cfg.RestartSec, cfg.WantedBy)
}

func runSystemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return fmt.Errorf("systemctl %s failed: %w", strings.Join(args, " "), err)
		}
		return fmt.Errorf("systemctl %s failed: %s", strings.Join(args, " "), msg)
	}
	return nil
}

func systemdUnitPath(serviceName string) string {
	return filepath.Join("/etc/systemd/system", serviceName+".service")
}
