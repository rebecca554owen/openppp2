package api

import (
	"encoding/json"
	"net/http"
)

type registerBinaryRequest struct {
	Path string `json:"path"`
}

func (s *Server) handleListBinaries(w http.ResponseWriter, r *http.Request) {
	items, err := s.binaryMgr.List()
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	Success(w, items)
}

func (s *Server) handleRegisterBinary(w http.ResponseWriter, r *http.Request) {
	var req registerBinaryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	info, err := s.binaryMgr.Register(req.Path)
	if err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	Success(w, info)
}

func (s *Server) handleDiscoverBinaries(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("dir")
	if dir == "" {
		dir = "."
	}

	items, err := s.binaryMgr.Discover(dir)
	if err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}

	Success(w, items)
}

func (s *Server) handleRemoveBinary(w http.ResponseWriter, r *http.Request) {
	if err := s.binaryMgr.Remove(r.PathValue("id")); err != nil {
		Error(w, http.StatusNotFound, err.Error())
		return
	}
	Success(w, map[string]bool{"deleted": true})
}
