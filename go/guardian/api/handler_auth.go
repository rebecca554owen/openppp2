package api

import (
	"encoding/json"
	"net/http"

	"ppp/guardian/auth"
)

type loginRequest struct {
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if s.authCfg.AuthEnabled && req.Password != s.jwtSecret {
		Error(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	token, expiry, err := s.issueToken()
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	Success(w, map[string]any{"token": token, "expiresAt": expiry})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	oldToken := bearerToken(r.Header.Get("Authorization"))
	if oldToken == "" || !s.tokenStore.Validate(oldToken) {
		Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if _, err := auth.ValidateToken(oldToken, s.jwtSecret); err != nil {
		Error(w, http.StatusUnauthorized, err.Error())
		return
	}
	s.tokenStore.Remove(oldToken)
	token, expiry, err := s.issueToken()
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	Success(w, map[string]any{"token": token, "expiresAt": expiry})
}

func (s *Server) issueToken() (string, any, error) {
	secret := s.jwtSecret
	if secret == "" {
		secret = "guardian-dev-secret"
	}
	token, err := auth.GenerateToken(secret, s.authCfg.TokenExpiryHours)
	if err != nil {
		return "", nil, err
	}
	claims, err := auth.ValidateToken(token, secret)
	if err != nil {
		return "", nil, err
	}
	s.jwtSecret = secret
	s.tokenStore.Add(token, claims.ExpiresAt)
	return token, claims.ExpiresAt, nil
}

type changePasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.NewPassword == "" {
		Error(w, http.StatusBadRequest, "new password is required")
		return
	}
	currentSecret := s.jwtSecret
	if currentSecret == "" {
		currentSecret = "guardian-dev-secret"
	}
	if s.authCfg.AuthEnabled && req.OldPassword != currentSecret {
		Error(w, http.StatusUnauthorized, "invalid current password")
		return
	}
	s.jwtSecret = req.NewPassword
	s.authCfg.JWTSecret = req.NewPassword
	if !s.authCfg.AuthEnabled && req.NewPassword != "" {
		s.authCfg.AuthEnabled = true
	}
	s.tokenStore.Clear()
	Success(w, map[string]any{"ok": true, "message": "password updated, all tokens invalidated"})
}
