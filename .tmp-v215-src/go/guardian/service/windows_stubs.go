//go:build !windows

package service

import "fmt"

type WindowsServiceConfig struct {
	ServiceName string
	DisplayName string
	Description string
	BinaryPath  string
}

func InstallWindowsService(cfg WindowsServiceConfig) error {
	return fmt.Errorf("Windows service installation is not available on %s", currentPlatform())
}

func UninstallWindowsService(serviceName string) error {
	return fmt.Errorf("Windows service uninstallation is not available on %s", currentPlatform())
}

func WindowsServiceStatus(serviceName string) (string, error) {
	return "unknown", fmt.Errorf("Windows service status is not available on %s", currentPlatform())
}
