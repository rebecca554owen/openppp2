package api

import (
	"net/http"
	"strings"
	"time"
)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			s.logger.Info("request completed",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"duration", time.Since(start),
			)
		}()

		if s.authCfg.AuthEnabled && requiresAuth(r.URL.Path) {
			token := bearerToken(r.Header.Get("Authorization"))
			if token == "" || !s.tokenStore.Validate(token) {
				Error(sw, http.StatusUnauthorized, "unauthorized")
				return
			}
		}

		next.ServeHTTP(sw, r)
	})
}

func requiresAuth(path string) bool {
	if strings.HasPrefix(path, "/api/v1/auth/") {
		return false
	}
	if path == "/api/v1/status" {
		return false
	}
	if strings.HasPrefix(path, "/api/v1/ws/") || strings.HasPrefix(path, "/api/v1/sse/") {
		return false
	}
	if !strings.HasPrefix(path, "/api/") {
		return false
	}
	return true
}

func bearerToken(header string) string {
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
}
