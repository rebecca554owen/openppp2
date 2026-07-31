package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"ppp/guardian/instance"
)

type instanceCreateRequest struct {
	Name        string            `json:"name"`
	Binary      string            `json:"binary"`
	WorkDir     string            `json:"workDir"`
	ConfigPath  string            `json:"configPath"`
	Args        []string          `json:"args"`
	Env         map[string]string `json:"env"`
	StopSignal  string            `json:"stopSignal"`
	StopWaitMs  int               `json:"stopWaitMs"`
	AutoRestart *autoRestartReq   `json:"autoRestart"`
	HealthCheck *healthCheckReq   `json:"healthCheck"`
	LogLines    int               `json:"logLines"`
	TUIEnabled  bool              `json:"tuiEnabled"`
}

type autoRestartReq struct {
	Enabled      bool `json:"enabled"`
	MaxRetries   int  `json:"maxRetries"`
	RetryDelayMs int  `json:"retryDelayMs"`
	ResetAfterMs int  `json:"resetAfterMs"`
}

type healthCheckReq struct {
	Enabled      bool   `json:"enabled"`
	IntervalMs   int    `json:"intervalMs"`
	TCPPort      int    `json:"tcpPort"`
	HTTPEndpoint string `json:"httpEndpoint"`
}

func (s *Server) handleCreateInstance(w http.ResponseWriter, r *http.Request) {
	var req instanceCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg := instance.Config{
		Name:       req.Name,
		Binary:     req.Binary,
		WorkDir:    req.WorkDir,
		ConfigPath: req.ConfigPath,
		Args:       req.Args,
		Env:        req.Env,
		StopSignal: req.StopSignal,
		StopWaitMs: req.StopWaitMs,
		LogLines:   req.LogLines,
		TUIEnabled: req.TUIEnabled,
	}
	if req.AutoRestart != nil {
		cfg.AutoRestart = instance.AutoRestartConfig{
			Enabled:      req.AutoRestart.Enabled,
			MaxRetries:   req.AutoRestart.MaxRetries,
			RetryDelayMs: req.AutoRestart.RetryDelayMs,
			ResetAfterMs: req.AutoRestart.ResetAfterMs,
		}
	}
	if req.HealthCheck != nil {
		cfg.HealthCheck = instance.HealthCheckConfig{
			Enabled:      req.HealthCheck.Enabled,
			IntervalMs:   req.HealthCheck.IntervalMs,
			TCPPort:      req.HealthCheck.TCPPort,
			HTTPEndpoint: req.HealthCheck.HTTPEndpoint,
		}
	}
	if err := s.instanceMgr.Add(req.Name, cfg); err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.authCfg.OnConfigChanged != nil {
		if err := s.authCfg.OnConfigChanged(); err != nil {
			_ = s.instanceMgr.Remove(req.Name)
			Error(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	status, _ := s.instanceMgr.Status(req.Name)
	JSON(w, http.StatusCreated, status)
}

func (s *Server) handleUpdateInstance(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req instanceCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = name
	cfg := instance.Config{
		Name:       name,
		Binary:     req.Binary,
		WorkDir:    req.WorkDir,
		ConfigPath: req.ConfigPath,
		Args:       req.Args,
		Env:        req.Env,
		StopSignal: req.StopSignal,
		StopWaitMs: req.StopWaitMs,
		LogLines:   req.LogLines,
		TUIEnabled: req.TUIEnabled,
	}
	if req.AutoRestart != nil {
		cfg.AutoRestart = instance.AutoRestartConfig{
			Enabled:      req.AutoRestart.Enabled,
			MaxRetries:   req.AutoRestart.MaxRetries,
			RetryDelayMs: req.AutoRestart.RetryDelayMs,
			ResetAfterMs: req.AutoRestart.ResetAfterMs,
		}
	}
	if req.HealthCheck != nil {
		cfg.HealthCheck = instance.HealthCheckConfig{
			Enabled:      req.HealthCheck.Enabled,
			IntervalMs:   req.HealthCheck.IntervalMs,
			TCPPort:      req.HealthCheck.TCPPort,
			HTTPEndpoint: req.HealthCheck.HTTPEndpoint,
		}
	}
	if err := s.instanceMgr.Update(name, cfg); err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.authCfg.OnConfigChanged != nil {
		if err := s.authCfg.OnConfigChanged(); err != nil {
			Error(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	status, err := s.instanceMgr.Status(name)
	if err != nil {
		Error(w, http.StatusNotFound, err.Error())
		return
	}
	Success(w, status)
}

func (s *Server) handleRemoveInstance(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.instanceMgr.Remove(name); err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.authCfg.OnConfigChanged != nil {
		if err := s.authCfg.OnConfigChanged(); err != nil {
			Error(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	Success(w, map[string]any{"ok": true, "name": name})
}

func (s *Server) handleListInstances(w http.ResponseWriter, r *http.Request) {
	Success(w, s.instanceMgr.List())
}

func (s *Server) handleGetInstance(w http.ResponseWriter, r *http.Request) {
	status, err := s.instanceMgr.Status(r.PathValue("name"))
	if err != nil {
		Error(w, http.StatusNotFound, err.Error())
		return
	}
	Success(w, status)
}

func (s *Server) handleStartInstance(w http.ResponseWriter, r *http.Request) {
	s.handleInstanceAction(w, r, s.instanceMgr.Start)
}

func (s *Server) handleStopInstance(w http.ResponseWriter, r *http.Request) {
	s.handleInstanceAction(w, r, s.instanceMgr.Stop)
}

func (s *Server) handleRestartInstance(w http.ResponseWriter, r *http.Request) {
	s.handleInstanceAction(w, r, s.instanceMgr.Restart)
}

func (s *Server) handleInstanceAction(w http.ResponseWriter, r *http.Request, fn func(string) error) {
	name := r.PathValue("name")
	if err := fn(name); err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	status, err := s.instanceMgr.Status(name)
	if err != nil {
		Error(w, http.StatusNotFound, err.Error())
		return
	}
	Success(w, status)
}

func (s *Server) handleInstanceLogs(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	stream := r.URL.Query().Get("stream")
	if stream == "" {
		stream = "all"
	}
	n := s.authCfg.LogLines
	if qs := r.URL.Query().Get("n"); qs != "" {
		if parsed, err := strconv.Atoi(qs); err == nil && parsed > 0 {
			n = parsed
		}
	}
	logs := s.instanceMgr.Logs(name, stream, n)
	if logs == nil {
		logs = []instance.LogEntry{}
	}
	Success(w, logs)
}
