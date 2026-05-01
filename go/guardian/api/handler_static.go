package api

import (
	"io/fs"
	"net/http"
	"strings"
)

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if s.webuiFS == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><body><h1>Guardian API running</h1></body></html>"))
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}

	sub, err := fs.Sub(s.webuiFS, "webui/dist")
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	http.FileServer(http.FS(sub)).ServeHTTP(w, r)
}
