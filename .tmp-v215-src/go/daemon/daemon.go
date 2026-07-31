package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Daemon struct {
	mu        sync.Mutex
	cfg       *Config
	cmd       *exec.Cmd
	startedAt time.Time
	stoppedAt time.Time
	lastExit  *ExitState
	logs      *LogBuffer
	proxy     *httputil.ReverseProxy
}

type ExitState struct {
	Code    int       `json:"code"`
	Error   string    `json:"error,omitempty"`
	At      time.Time `json:"at"`
	Success bool      `json:"success"`
}

type StatusResponse struct {
	Name        string     `json:"name"`
	Running     bool       `json:"running"`
	PID         int        `json:"pid,omitempty"`
	StartedAt   *time.Time `json:"startedAt,omitempty"`
	StoppedAt   *time.Time `json:"stoppedAt,omitempty"`
	ConfigPath  string     `json:"configPath"`
	WorkDir     string     `json:"workDir"`
	Binary      string     `json:"binary"`
	Args        []string   `json:"args"`
	ManagedAPI  string     `json:"managedApi,omitempty"`
	LastExit    *ExitState `json:"lastExit,omitempty"`
	TrackedLogs int        `json:"trackedLogs"`
}

type LogEntry struct {
	At     time.Time `json:"at"`
	Stream string    `json:"stream"`
	Text   string    `json:"text"`
}

type LogBuffer struct {
	mu      sync.Mutex
	limit   int
	entries []LogEntry
}

func NewLogBuffer(limit int) *LogBuffer {
	if limit <= 0 {
		limit = 400
	}
	return &LogBuffer{limit: limit, entries: make([]LogEntry, 0, limit)}
}

func (b *LogBuffer) Add(stream, text string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = append(b.entries, LogEntry{At: time.Now(), Stream: stream, Text: text})
	if len(b.entries) > b.limit {
		b.entries = append([]LogEntry(nil), b.entries[len(b.entries)-b.limit:]...)
	}
}

func (b *LogBuffer) All() []LogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]LogEntry, len(b.entries))
	copy(out, b.entries)
	return out
}

func NewDaemon(cfg *Config) (*Daemon, error) {
	d := &Daemon{
		cfg:  cfg,
		logs: NewLogBuffer(cfg.Instance.LogLines),
	}

	if cfg.ManagedAPI.BaseURL != "" {
		target, err := url.Parse(cfg.ManagedAPI.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("parse managed api url: %w", err)
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		originalDirector := proxy.Director
		proxy.Director = func(r *http.Request) {
			originalDirector(r)
			prefix := cfg.ManagedAPI.Prefix
			if prefix == "" {
				prefix = "/api/managed/"
			}
			path := strings.TrimPrefix(r.URL.Path, prefix)
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			r.URL.Path = path
		}
		d.proxy = proxy
	}

	return d, nil
}

func (d *Daemon) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", d.handleIndex)
	mux.HandleFunc("/api/status", d.handleStatus)
	mux.HandleFunc("/api/config", d.handleConfig)
	mux.HandleFunc("/api/start", d.handleStart)
	mux.HandleFunc("/api/stop", d.handleStop)
	mux.HandleFunc("/api/restart", d.handleRestart)
	mux.HandleFunc("/api/logs", d.handleLogs)
	mux.HandleFunc("/api/managed/", d.handleManagedProxy)
	return mux
}

func (d *Daemon) Shutdown() {
	_ = d.Stop()
}

func (d *Daemon) Status() StatusResponse {
	trackedLogs := len(d.logs.All())

	d.mu.Lock()
	defer d.mu.Unlock()

	status := StatusResponse{
		Name:        d.cfg.Instance.Name,
		Running:     d.cmd != nil && d.cmd.Process != nil,
		ConfigPath:  d.cfg.Instance.ConfigPath,
		WorkDir:     d.cfg.Instance.WorkDir,
		Binary:      d.cfg.Instance.Binary,
		Args:        append([]string(nil), d.cfg.Instance.Args...),
		ManagedAPI:  d.cfg.ManagedAPI.BaseURL,
		LastExit:    d.lastExit,
		TrackedLogs: trackedLogs,
	}
	if !d.startedAt.IsZero() {
		t := d.startedAt
		status.StartedAt = &t
	}
	if !d.stoppedAt.IsZero() {
		t := d.stoppedAt
		status.StoppedAt = &t
	}
	if d.cmd != nil && d.cmd.Process != nil {
		status.PID = d.cmd.Process.Pid
	}
	return status
}

func (d *Daemon) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.cmd != nil && d.cmd.Process != nil {
		return errors.New("instance already running")
	}

	cmd := exec.Command(d.cfg.Instance.Binary, d.cfg.Instance.Args...)
	cmd.Dir = d.cfg.Instance.WorkDir
	cmd.Env = append([]string(nil), os.Environ()...)
	for k, v := range d.cfg.Instance.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	d.cmd = cmd
	d.startedAt = time.Now()
	d.stoppedAt = time.Time{}
	d.lastExit = nil

	go d.capturePipe("stdout", stdout)
	go d.capturePipe("stderr", stderr)
	go d.waitProcess(cmd)
	return nil
}

func (d *Daemon) capturePipe(stream string, r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		d.logs.Add(stream, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		d.logs.Add("daemon", stream+": "+err.Error())
	}
}

func (d *Daemon) waitProcess(cmd *exec.Cmd) {
	err := cmd.Wait()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cmd != cmd {
		return
	}
	state := &ExitState{At: time.Now(), Success: err == nil}
	if err != nil {
		state.Error = err.Error()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			state.Code = exitErr.ExitCode()
		}
	}
	d.lastExit = state
	d.stoppedAt = state.At
	d.cmd = nil
	if state.Error != "" {
		d.logs.Add("daemon", "process exited: "+state.Error)
	} else {
		d.logs.Add("daemon", "process exited cleanly")
	}
}

func (d *Daemon) Stop() error {
	d.mu.Lock()
	cmd := d.cmd
	stopSignal := d.cfg.Instance.StopSignal
	stopWait := time.Duration(d.cfg.Instance.StopWaitMs) * time.Millisecond
	d.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}

	var sig os.Signal = os.Interrupt
	if strings.EqualFold(stopSignal, "term") || strings.EqualFold(stopSignal, "sigterm") {
		sig = syscall.SIGTERM
	}
	if err := cmd.Process.Signal(sig); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), stopWait)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if err := cmd.Process.Kill(); err != nil {
				return err
			}
			return nil
		case <-ticker.C:
			d.mu.Lock()
			alive := d.cmd == cmd && d.cmd != nil
			d.mu.Unlock()
			if !alive {
				return nil
			}
		}
	}
}

func (d *Daemon) Restart() error {
	if err := d.Stop(); err != nil {
		return err
	}
	return d.Start()
}

func (d *Daemon) ReadConfig() ([]byte, error) {
	return os.ReadFile(d.cfg.Instance.ConfigPath)
}

func (d *Daemon) WriteConfig(content []byte) error {
	content = bytes.TrimSpace(content)
	if len(content) == 0 {
		return errors.New("empty config content")
	}
	var jsonCheck any
	if err := json.Unmarshal(content, &jsonCheck); err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	return os.WriteFile(d.cfg.Instance.ConfigPath, append(content, '\n'), 0644)
}
