package api

import (
	"encoding/json"
	"net/http"
)

func JSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if v == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

func Error(w http.ResponseWriter, code int, message string) {
	JSON(w, code, map[string]string{"error": message})
}

func Success(w http.ResponseWriter, v any) {
	JSON(w, http.StatusOK, v)
}
