package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Listen     string            `json:"listen"`
	ManagedAPI ManagedAPIConfig  `json:"managedApi"`
	Instance   InstanceConfig    `json:"instance"`
	UI         UIConfig          `json:"ui"`
}

type ManagedAPIConfig struct {
	BaseURL string `json:"baseUrl"`
	Prefix  string `json:"prefix"`
}

type InstanceConfig struct {
	Name       string            `json:"name"`
	Binary     string            `json:"binary"`
	WorkDir    string            `json:"workDir"`
	ConfigPath string            `json:"configPath"`
	Args       []string          `json:"args"`
	Env        map[string]string `json:"env"`
	StopSignal string            `json:"stopSignal"`
	StopWaitMs int               `json:"stopWaitMs"`
	LogLines   int               `json:"logLines"`
}

type UIConfig struct {
	Title string `json:"title"`
}

func DefaultConfig() *Config {
	return &Config{
		Listen: ":18080",
		ManagedAPI: ManagedAPIConfig{
			BaseURL: "http://127.0.0.1:10000",
			Prefix:  "/api/managed/",
		},
		Instance: InstanceConfig{
			Name:       "ppp",
			Binary:     "./openppp2",
			WorkDir:    ".",
			ConfigPath: "./appsettings.json",
			Args: []string{
				"--mode=client",
				"--configuration=./appsettings.json",
			},
			Env:        map[string]string{},
			StopSignal: "interrupt",
			StopWaitMs: 5000,
			LogLines:   400,
		},
		UI: UIConfig{
			Title: "OpenPPP2 Daemon",
		},
	}
}

func LoadConfigFromArgs(args []string) (*Config, error) {
	path := "appsettings.json"
	for _, arg := range args {
		if strings.HasPrefix(arg, "--configuration=") {
			path = strings.TrimPrefix(arg, "--configuration=")
		}
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load daemon config: %w", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(content, cfg); err != nil {
		return nil, fmt.Errorf("parse daemon config: %w", err)
	}

	if cfg.Listen == "" {
		cfg.Listen = ":18080"
	}
	if cfg.ManagedAPI.Prefix == "" {
		cfg.ManagedAPI.Prefix = "/api/managed/"
	}
	if cfg.Instance.Name == "" {
		cfg.Instance.Name = "ppp"
	}
	if cfg.Instance.Binary == "" {
		return nil, errors.New("instance.binary is required")
	}
	if cfg.Instance.ConfigPath == "" {
		return nil, errors.New("instance.configPath is required")
	}
	if cfg.Instance.WorkDir == "" {
		cfg.Instance.WorkDir = "."
	}
	if cfg.Instance.StopWaitMs <= 0 {
		cfg.Instance.StopWaitMs = 5000
	}
	if cfg.Instance.LogLines <= 0 {
		cfg.Instance.LogLines = 400
	}
	if cfg.UI.Title == "" {
		cfg.UI.Title = "OpenPPP2 Daemon"
	}

	workDir, err := filepath.Abs(cfg.Instance.WorkDir)
	if err != nil {
		return nil, err
	}
	cfg.Instance.WorkDir = workDir

	if !filepath.IsAbs(cfg.Instance.ConfigPath) {
		cfg.Instance.ConfigPath = filepath.Join(cfg.Instance.WorkDir, cfg.Instance.ConfigPath)
	}

	return cfg, nil
}
