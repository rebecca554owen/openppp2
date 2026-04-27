package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

type ConfigPayload struct {
	Content string `json:"content"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (d *Daemon) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, indexHTML(d.cfg.UI.Title))
}

func (d *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.Status())
}

func (d *Daemon) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		content, err := d.ReadConfig()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, ConfigPayload{Content: string(content)})
	case http.MethodPut, http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		payload := ConfigPayload{}
		content := body
		if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			if err := json.Unmarshal(body, &payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			content = []byte(payload.Content)
		}
		if err := d.WriteConfig(content); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (d *Daemon) handleStart(w http.ResponseWriter, r *http.Request) {
	if err := d.Start(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, d.Status())
}

func (d *Daemon) handleStop(w http.ResponseWriter, r *http.Request) {
	if err := d.Stop(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, d.Status())
}

func (d *Daemon) handleRestart(w http.ResponseWriter, r *http.Request) {
	if err := d.Restart(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, d.Status())
}

func (d *Daemon) handleLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": d.logs.All()})
}

func (d *Daemon) handleManagedProxy(w http.ResponseWriter, r *http.Request) {
	if d.proxy == nil {
		http.NotFound(w, r)
		return
	}
	d.proxy.ServeHTTP(w, r)
}

func indexHTML(title string) string {
	return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>` + title + `</title>
  <style>
    body { font-family: sans-serif; margin: 24px; max-width: 960px; }
    textarea { width: 100%; min-height: 260px; font-family: monospace; }
    button { margin-right: 8px; }
    pre { background: #111; color: #ddd; padding: 12px; overflow: auto; }
  </style>
</head>
<body>
  <h1>` + title + `</h1>
  <p>Single-instance local daemon for managing one ppp process and proxying the managed API.</p>

  <h2>Status</h2>
  <pre id="status">loading...</pre>
  <button onclick="startInstance()">Start</button>
  <button onclick="stopInstance()">Stop</button>
  <button onclick="restartInstance()">Restart</button>

  <h2>Config</h2>
  <textarea id="config"></textarea>
  <div>
    <button onclick="loadConfig()">Reload Config</button>
    <button onclick="saveConfig()">Save Config</button>
  </div>

  <h2>Logs</h2>
  <pre id="logs">loading...</pre>

  <script>
    async function refreshStatus() {
      const res = await fetch('/api/status');
      document.getElementById('status').textContent = JSON.stringify(await res.json(), null, 2);
    }
    async function loadConfig() {
      const res = await fetch('/api/config');
      const data = await res.json();
      document.getElementById('config').value = data.content || '';
    }
    async function saveConfig() {
      await fetch('/api/config', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({content: document.getElementById('config').value})
      });
      await refreshStatus();
    }
    async function startInstance() { await fetch('/api/start', {method: 'POST'}); await refreshStatus(); await refreshLogs(); }
    async function stopInstance() { await fetch('/api/stop', {method: 'POST'}); await refreshStatus(); await refreshLogs(); }
    async function restartInstance() { await fetch('/api/restart', {method: 'POST'}); await refreshStatus(); await refreshLogs(); }
    async function refreshLogs() {
      const res = await fetch('/api/logs');
      const data = await res.json();
      document.getElementById('logs').textContent = (data.items || []).map(x => '[' + x.at + '] ' + x.stream + ': ' + x.text).join('\n');
    }
    refreshStatus();
    loadConfig();
    refreshLogs();
    setInterval(refreshStatus, 3000);
    setInterval(refreshLogs, 3000);
  </script>
</body>
</html>`
}
