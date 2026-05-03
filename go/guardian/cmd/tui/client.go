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
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	Token   string
	client  *http.Client
}

type StatusResponse struct {
	Version       string `json:"version"`
	Uptime        string `json:"uptime"`
	InstanceCount int    `json:"instanceCount"`
}

type InstanceResponse struct {
	Name         string     `json:"name"`
	Running      bool       `json:"running"`
	PID          int        `json:"pid,omitempty"`
	StartedAt    *time.Time `json:"startedAt,omitempty"`
	StoppedAt    *time.Time `json:"stoppedAt,omitempty"`
	Binary       string     `json:"binary"`
	WorkDir      string     `json:"workDir"`
	ConfigPath   string     `json:"configPath"`
	Args         []string   `json:"args"`
	LastExit     *ExitState `json:"lastExit,omitempty"`
	AutoRestart  bool       `json:"autoRestart"`
	RestartCount int        `json:"restartCount"`
}

type ExitState struct {
	Code    int       `json:"code"`
	Error   string    `json:"error,omitempty"`
	At      time.Time `json:"at"`
	Success bool      `json:"success"`
}

type LogEntry struct {
	At     time.Time `json:"at"`
	Stream string    `json:"stream"`
	Text   string    `json:"text"`
}

type ProfileInfo struct {
	Name      string    `json:"name"`
	Path      string    `json:"path,omitempty"`
	Size      int64     `json:"size"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type Profile struct {
	Name      string    `json:"name"`
	Path      string    `json:"path,omitempty"`
	Size      int64     `json:"size"`
	UpdatedAt time.Time `json:"updatedAt"`
	Content   string    `json:"content"`
}

type BinaryInfo struct {
	ID      string    `json:"id"`
	Path    string    `json:"path"`
	Version string    `json:"version"`
	SHA256  string    `json:"sha256"`
	Size    int64     `json:"size"`
	Arch    string    `json:"arch"`
	AddedAt time.Time `json:"addedAt"`
	Active  bool      `json:"active"`
}

type DiscoveredBinary struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Arch   string `json:"arch"`
	Name   string `json:"name"`
}

type Event struct {
	Type    string    `json:"type"`
	Name    string    `json:"name"`
	At      time.Time `json:"at"`
	Message string    `json:"message,omitempty"`
}

type InstanceCreateRequest struct {
	Name       string            `json:"name"`
	Binary     string            `json:"binary"`
	WorkDir    string            `json:"workDir,omitempty"`
	ConfigPath string            `json:"configPath"`
	Args       []string          `json:"args,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	LogLines   int               `json:"logLines,omitempty"`
}

type apiError struct {
	Error string `json:"error"`
}

func (c *Client) Status() (*StatusResponse, error) {
	var out StatusResponse
	if err := c.doJSON(context.Background(), http.MethodGet, "/api/v1/status", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ListInstances() ([]InstanceResponse, error) {
	var out []InstanceResponse
	return out, c.doJSON(context.Background(), http.MethodGet, "/api/v1/instances", nil, &out)
}

func (c *Client) GetInstance(name string) (*InstanceResponse, error) {
	var out InstanceResponse
	if err := c.doJSON(context.Background(), http.MethodGet, "/api/v1/instances/"+url.PathEscape(name), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CreateInstance(cfg InstanceCreateRequest) (*InstanceResponse, error) {
	var out InstanceResponse
	if err := c.doJSON(context.Background(), http.MethodPost, "/api/v1/instances", cfg, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) RemoveInstance(name string) error {
	return c.doJSON(context.Background(), http.MethodDelete, "/api/v1/instances/"+url.PathEscape(name), nil, nil)
}

func (c *Client) StartInstance(name string) (*InstanceResponse, error) {
	return c.instanceAction(name, "start")
}

func (c *Client) StopInstance(name string) (*InstanceResponse, error) {
	return c.instanceAction(name, "stop")
}

func (c *Client) RestartInstance(name string) (*InstanceResponse, error) {
	return c.instanceAction(name, "restart")
}

func (c *Client) GetLogs(name string, n int) ([]LogEntry, error) {
	path := fmt.Sprintf("/api/v1/instances/%s/logs?n=%d", url.PathEscape(name), n)
	var out []LogEntry
	return out, c.doJSON(context.Background(), http.MethodGet, path, nil, &out)
}

func (c *Client) ListProfiles() ([]ProfileInfo, error) {
	var out []ProfileInfo
	return out, c.doJSON(context.Background(), http.MethodGet, "/api/v1/profiles", nil, &out)
}

func (c *Client) GetProfile(name string) (*Profile, error) {
	var out Profile
	if err := c.doJSON(context.Background(), http.MethodGet, "/api/v1/profiles/"+url.PathEscape(name), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) SaveProfile(name string, content string) error {
	return c.doJSON(context.Background(), http.MethodPut, "/api/v1/profiles/"+url.PathEscape(name), map[string]string{"content": content}, nil)
}

func (c *Client) DeleteProfile(name string) error {
	return c.doJSON(context.Background(), http.MethodDelete, "/api/v1/profiles/"+url.PathEscape(name), nil, nil)
}

func (c *Client) ListBinaries() ([]BinaryInfo, error) {
	var out []BinaryInfo
	return out, c.doJSON(context.Background(), http.MethodGet, "/api/v1/binaries", nil, &out)
}

func (c *Client) DiscoverBinaries(dir string) ([]DiscoveredBinary, error) {
	path := "/api/v1/binaries/discover?dir=" + url.QueryEscape(dir)
	var out []DiscoveredBinary
	return out, c.doJSON(context.Background(), http.MethodGet, path, nil, &out)
}

func (c *Client) RegisterBinary(path string) (*BinaryInfo, error) {
	var out BinaryInfo
	if err := c.doJSON(context.Background(), http.MethodPost, "/api/v1/binaries", map[string]string{"path": path}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) RemoveBinary(id string) error {
	return c.doJSON(context.Background(), http.MethodDelete, "/api/v1/binaries/"+url.PathEscape(id), nil, nil)
}

func (c *Client) SubscribeLogs(ctx context.Context, name string) (<-chan LogEntry, error) {
	ch := make(chan LogEntry, 100)
	req, err := c.newRequest(ctx, http.MethodGet, "/api/v1/sse/logs/"+url.PathEscape(name), nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	if c.Token != "" {
		q.Set("token", c.Token)
	}
	req.URL.RawQuery = q.Encode()
	go func() {
		defer close(ch)
		_ = c.consumeSSE(req, func(data []byte) error {
			var entry LogEntry
			if err := json.Unmarshal(data, &entry); err != nil {
				return err
			}
			select {
			case ch <- entry:
			case <-ctx.Done():
			}
			return nil
		})
	}()
	return ch, nil
}

func (c *Client) SubscribeEvents(ctx context.Context) (<-chan Event, error) {
	ch := make(chan Event, 100)
	req, err := c.newRequest(ctx, http.MethodGet, "/api/v1/sse/events", nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	if c.Token != "" {
		q.Set("token", c.Token)
	}
	req.URL.RawQuery = q.Encode()
	go func() {
		defer close(ch)
		_ = c.consumeSSE(req, func(data []byte) error {
			var event Event
			if err := json.Unmarshal(data, &event); err != nil {
				return err
			}
			select {
			case ch <- event:
			case <-ctx.Done():
			}
			return nil
		})
	}()
	return ch, nil
}

func (c *Client) instanceAction(name string, action string) (*InstanceResponse, error) {
	var out InstanceResponse
	path := fmt.Sprintf("/api/v1/instances/%s/%s", url.PathEscape(name), action)
	if err := c.doJSON(context.Background(), http.MethodPost, path, map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) doJSON(ctx context.Context, method string, path string, body any, out any) error {
	req, err := c.newRequest(ctx, method, path, body)
	if err != nil {
		return err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeAPIError(resp)
	}
	if out == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) newRequest(ctx context.Context, method string, path string, body any) (*http.Request, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	return req, nil
}

func (c *Client) consumeSSE(req *http.Request, onData func([]byte) error) error {
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeAPIError(resp)
	}
	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if len(lines) > 0 {
				payload := strings.Join(lines, "\n")
				if err := onData([]byte(payload)); err != nil {
					return err
				}
				lines = lines[:0]
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			lines = append(lines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func (c *Client) httpClient() *http.Client {
	if c.client != nil {
		return c.client
	}
	return http.DefaultClient
}

func decodeAPIError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	var apiErr apiError
	if err := json.Unmarshal(body, &apiErr); err == nil && apiErr.Error != "" {
		return fmt.Errorf("api error (%d): %s", resp.StatusCode, apiErr.Error)
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		trimmed = resp.Status
	}
	return fmt.Errorf("api error (%d): %s", resp.StatusCode, trimmed)
}
