package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"ppp/guardian/binary"
	"ppp/guardian/instance"
	"ppp/guardian/profile"
)

type Guardian struct {
	cfg                       *GuardianConfig
	configPath                string
	instances                 *instance.Manager
	profiles                  *profile.Manager
	binaries                  *binary.Manager
	autoDiscoveredCount       int
	workingDirDiscoveredCount int
}

func NewGuardian(cfg *GuardianConfig, configPath string) (*Guardian, error) {
	g := &Guardian{
		cfg:        cfg,
		configPath: configPath,
		instances:  instance.NewManager(),
		profiles:   profile.NewManager(cfg.ProfilesDir, profile.BackupConfig{Enabled: cfg.Backup.Enabled, MaxBackups: cfg.Backup.MaxBackups, Dir: cfg.Backup.Dir}),
		binaries:   binary.NewManager(cfg.BinariesDir),
	}

	scanDirs := []string{".", "./", "../bin/", "../../bin/", "/usr/local/bin/"}
	seenDirs := make(map[string]struct{}, len(scanDirs))
	for _, dir := range scanDirs {
		cleanDir := filepath.Clean(dir)
		if _, seen := seenDirs[cleanDir]; seen {
			continue
		}
		seenDirs[cleanDir] = struct{}{}

		registered, err := g.binaries.AutoDiscover(dir)
		if err != nil {
			if os.IsNotExist(err) {
				log.Printf("guardian: auto-discovery skipped missing directory %s", cleanDir)
				continue
			}
			log.Printf("guardian: auto-discovery failed for %s: %v", cleanDir, err)
			continue
		}
		if len(registered) == 0 {
			log.Printf("guardian: auto-discovery found no ppp binaries in %s", cleanDir)
			continue
		}
		log.Printf("guardian: auto-discovered %d ppp binaries in %s", len(registered), cleanDir)
		g.autoDiscoveredCount += len(registered)
		if cleanDir == "." {
			g.workingDirDiscoveredCount = len(registered)
		}
	}

	for _, inst := range cfg.Instances {
		if !inst.Enabled {
			continue
		}
		if err := g.instances.Add(inst.Name, instance.Config{
			Name:       inst.Name,
			Binary:     inst.Binary,
			WorkDir:    inst.WorkDir,
			ConfigPath: inst.ConfigPath,
			Args:       inst.Args,
			Env:        inst.Env,
			StopSignal: inst.StopSignal,
			StopWaitMs: inst.StopWaitMs,
			AutoRestart: instance.AutoRestartConfig{
				Enabled:      inst.AutoRestart.Enabled,
				MaxRetries:   inst.AutoRestart.MaxRetries,
				RetryDelayMs: inst.AutoRestart.RetryDelayMs,
				ResetAfterMs: inst.AutoRestart.ResetAfterMs,
			},
			HealthCheck: instance.HealthCheckConfig{
				Enabled:      inst.HealthCheck.Enabled,
				IntervalMs:   inst.HealthCheck.IntervalMs,
				TCPPort:      inst.HealthCheck.TCPPort,
				HTTPEndpoint: inst.HealthCheck.HTTPEndpoint,
			},
			LogLines: inst.LogLines,
			TUIEnabled: inst.TUIEnabled,
		}); err != nil {
			return nil, fmt.Errorf("add instance %s: %w", inst.Name, err)
		}
	}

	return g, nil
}

func (g *Guardian) AutoDiscoveredCount() int {
	return g.autoDiscoveredCount
}

func (g *Guardian) WorkingDirDiscoveredCount() int {
	return g.workingDirDiscoveredCount
}

func (g *Guardian) Start() {
	for _, inst := range g.cfg.Instances {
		if !inst.Enabled {
			continue
		}
		if err := g.instances.Start(inst.Name); err != nil {
			log.Printf("instance %s start failed (will retry if auto-restart enabled): %v", inst.Name, err)
		}
	}
}

func (g *Guardian) Shutdown() {
	g.instances.Shutdown()
}

func (g *Guardian) InstanceManager() *instance.Manager {
	return g.instances
}

func (g *Guardian) ProfileManager() *profile.Manager {
	return g.profiles
}

func (g *Guardian) BinaryManager() *binary.Manager {
	return g.binaries
}

func (g *Guardian) Config() *GuardianConfig {
	return g.cfg
}

func (g *Guardian) SaveConfig() error {
	if g.configPath == "" {
		return fmt.Errorf("guardian config path is empty")
	}

	instances := g.instances.ListConfigs()
	savedInstances := make([]InstanceConfig, 0, len(instances))
	for _, inst := range instances {
		savedInstances = append(savedInstances, InstanceConfig{
			Name:       inst.Name,
			Enabled:    true,
			Binary:     inst.Binary,
			WorkDir:    inst.WorkDir,
			ConfigPath: inst.ConfigPath,
			Args:       append([]string(nil), inst.Args...),
			Env:        cloneStringMap(inst.Env),
			StopSignal: inst.StopSignal,
			StopWaitMs: inst.StopWaitMs,
			AutoRestart: AutoRestartConfig{
				Enabled:      inst.AutoRestart.Enabled,
				MaxRetries:   inst.AutoRestart.MaxRetries,
				RetryDelayMs: inst.AutoRestart.RetryDelayMs,
				ResetAfterMs: inst.AutoRestart.ResetAfterMs,
			},
			HealthCheck: HealthCheckConfig{
				Enabled:      inst.HealthCheck.Enabled,
				IntervalMs:   inst.HealthCheck.IntervalMs,
				TCPPort:      inst.HealthCheck.TCPPort,
				HTTPEndpoint: inst.HealthCheck.HTTPEndpoint,
			},
			LogLines: inst.LogLines,
			TUIEnabled: inst.TUIEnabled,
		})
	}

	g.cfg.Instances = savedInstances

	data, err := json.MarshalIndent(g.cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal guardian config: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(g.configPath), 0o755); err != nil {
		return fmt.Errorf("ensure config directory: %w", err)
	}
	if err := os.WriteFile(g.configPath, data, 0o644); err != nil {
		return fmt.Errorf("write guardian config: %w", err)
	}
	return nil
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return map[string]string{}
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
