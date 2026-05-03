//go:build windows

package service

import "fmt"

type WindowsServiceConfig struct {
	ServiceName string
	DisplayName string
	Description string
	BinaryPath  string
}

func InstallWindowsService(cfg WindowsServiceConfig) error {
	return fmt.Errorf("Windows service installation not yet implemented. Use: sc create %s binPath= \"%s\" start= auto", cfg.ServiceName, cfg.BinaryPath)
}

func UninstallWindowsService(serviceName string) error {
	return fmt.Errorf("Windows service uninstallation not yet implemented. Use: sc delete %s", serviceName)
}

func WindowsServiceStatus(serviceName string) (string, error) {
	return "unknown", fmt.Errorf("Windows service status check not yet implemented")
}
