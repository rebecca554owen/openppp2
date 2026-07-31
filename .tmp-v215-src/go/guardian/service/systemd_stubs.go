//go:build !linux

package service

import "fmt"

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
	return fmt.Errorf("systemd installation is only supported on Linux")
}

func UninstallSystemd(serviceName string) error {
	return fmt.Errorf("systemd uninstallation is only supported on Linux")
}

func SystemdStatus(serviceName string) (string, error) {
	return "unknown", fmt.Errorf("systemd status is only supported on Linux")
}
