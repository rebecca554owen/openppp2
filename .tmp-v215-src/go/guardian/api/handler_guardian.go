package api

import (
	"net/http"
	"time"
)

func (s *Server) handleGuardianStatus(w http.ResponseWriter, r *http.Request) {
	binaries, err := s.binaryMgr.List()
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	Success(w, map[string]any{
		"version":       "0.1.0",
		"uptime":        fmtDuration(time.Since(s.startedAt)),
		"instanceCount": len(s.instanceMgr.List()),
		"binariesCount": len(binaries),
	})
}

func (s *Server) handleSaveGuardianConfig(w http.ResponseWriter, r *http.Request) {
	if s.authCfg.OnConfigChanged == nil {
		Error(w, http.StatusNotImplemented, "guardian config persistence is not configured")
		return
	}
	if err := s.authCfg.OnConfigChanged(); err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	Success(w, map[string]any{"ok": true})
}

func fmtDuration(d time.Duration) string {
	return d.Truncate(time.Second).String()
}
