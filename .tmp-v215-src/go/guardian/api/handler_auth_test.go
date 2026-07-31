package api

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginRejectsEmptyPasswordWhenSecretIsEmpty(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil, nil, nil, &GuardianServerConfig{AuthEnabled: true}, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"password":""}`))
	res := httptest.NewRecorder()

	server.handleLogin(res, req)

	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", res.Code, http.StatusServiceUnavailable, res.Body.String())
	}
}

func TestLoginRejectsEmptyPasswordWhenSecretIsNonEmpty(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil, nil, nil, &GuardianServerConfig{AuthEnabled: true, JWTSecret: "secret"}, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"password":""}`))
	res := httptest.NewRecorder()

	server.handleLogin(res, req)

	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", res.Code, http.StatusUnauthorized, res.Body.String())
	}
}

func TestLoginAcceptsConfiguredSecret(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil, nil, nil, &GuardianServerConfig{AuthEnabled: true, JWTSecret: "secret"}, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"password":"secret"}`))
	res := httptest.NewRecorder()

	server.handleLogin(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", res.Code, http.StatusOK, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "token") {
		t.Fatalf("body = %s, want token", res.Body.String())
	}
}

func TestIssueTokenRejectsEmptySecret(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil, nil, nil, &GuardianServerConfig{AuthEnabled: true}, nil)

	token, _, err := server.issueToken()
	if err == nil {
		t.Fatalf("issueToken() error = nil, token=%q; want empty-secret failure", token)
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("issueToken() error = %v, want not configured", err)
	}
}

func TestChangePasswordRejectsFallbackSecretWhenSecretIsEmpty(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil, nil, nil, &GuardianServerConfig{AuthEnabled: true}, nil)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/auth/password", bytes.NewBufferString(`{"oldPassword":"guardian-dev-secret","newPassword":"new-secret"}`))
	res := httptest.NewRecorder()

	server.handleChangePassword(res, req)

	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", res.Code, http.StatusServiceUnavailable, res.Body.String())
	}
}

func TestChangePasswordPersistsAuthChangeBeforeSuccess(t *testing.T) {
	var gotEnabled bool
	var gotSecret string
	server := NewServer("127.0.0.1:0", nil, nil, nil, &GuardianServerConfig{
		AuthEnabled: true,
		JWTSecret:   "old-secret",
		OnAuthChanged: func(enabled bool, jwtSecret string) error {
			gotEnabled = enabled
			gotSecret = jwtSecret
			return nil
		},
	}, nil)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/auth/password", bytes.NewBufferString(`{"oldPassword":"old-secret","newPassword":"new-secret"}`))
	res := httptest.NewRecorder()

	server.handleChangePassword(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", res.Code, http.StatusOK, res.Body.String())
	}
	if !gotEnabled || gotSecret != "new-secret" {
		t.Fatalf("OnAuthChanged(%v, %q), want true, new-secret", gotEnabled, gotSecret)
	}
	if server.jwtSecret != "new-secret" || server.authCfg.JWTSecret != "new-secret" || !server.authCfg.AuthEnabled {
		t.Fatalf("server auth state not updated after successful persistence")
	}
}

func TestChangePasswordDoesNotUpdateMemoryWhenPersistenceFails(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil, nil, nil, &GuardianServerConfig{
		AuthEnabled: true,
		JWTSecret:   "old-secret",
		OnAuthChanged: func(bool, string) error {
			return errors.New("persist failed")
		},
	}, nil)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/auth/password", bytes.NewBufferString(`{"oldPassword":"old-secret","newPassword":"new-secret"}`))
	res := httptest.NewRecorder()

	server.handleChangePassword(res, req)

	if res.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body=%s", res.Code, http.StatusInternalServerError, res.Body.String())
	}
	if server.jwtSecret != "old-secret" || server.authCfg.JWTSecret != "old-secret" {
		t.Fatalf("server auth state changed despite persistence failure")
	}
}
