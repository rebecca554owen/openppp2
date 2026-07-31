package api

import "net/http"

func (s *Server) registerRoutes() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/refresh", s.handleRefresh)
	mux.HandleFunc("PUT /api/v1/auth/password", s.handleChangePassword)

	mux.HandleFunc("GET /api/v1/instances", s.handleListInstances)
	mux.HandleFunc("POST /api/v1/instances", s.handleCreateInstance)
	mux.HandleFunc("GET /api/v1/instances/{name}", s.handleGetInstance)
	mux.HandleFunc("PUT /api/v1/instances/{name}", s.handleUpdateInstance)
	mux.HandleFunc("DELETE /api/v1/instances/{name}", s.handleRemoveInstance)
	mux.HandleFunc("POST /api/v1/instances/{name}/start", s.handleStartInstance)
	mux.HandleFunc("POST /api/v1/instances/{name}/stop", s.handleStopInstance)
	mux.HandleFunc("POST /api/v1/instances/{name}/restart", s.handleRestartInstance)
	mux.HandleFunc("GET /api/v1/instances/{name}/logs", s.handleInstanceLogs)

	mux.HandleFunc("GET /api/v1/profiles", s.handleListProfiles)
	mux.HandleFunc("GET /api/v1/profiles/{name}", s.handleGetProfile)
	mux.HandleFunc("PUT /api/v1/profiles/{name}", s.handleSaveProfile)
	mux.HandleFunc("DELETE /api/v1/profiles/{name}", s.handleDeleteProfile)
	mux.HandleFunc("POST /api/v1/profiles/{name}/validate", s.handleValidateProfile)
	mux.HandleFunc("GET /api/v1/profiles/{name}/backups", s.handleProfileBackups)
	mux.HandleFunc("POST /api/v1/profiles/{name}/restore/{backupId}", s.handleRestoreProfile)

	mux.HandleFunc("GET /api/v1/binaries", s.handleListBinaries)
	mux.HandleFunc("GET /api/v1/binaries/discover", s.handleDiscoverBinaries)
	mux.HandleFunc("POST /api/v1/binaries", s.handleRegisterBinary)
	mux.HandleFunc("DELETE /api/v1/binaries/{id}", s.handleRemoveBinary)

	mux.HandleFunc("GET /api/v1/status", s.handleGuardianStatus)
	mux.HandleFunc("PUT /api/v1/guardian/config", s.handleSaveGuardianConfig)
	mux.HandleFunc("GET /api/v1/service/status", s.handleServiceStatus)
	mux.HandleFunc("POST /api/v1/service/install", s.handleServiceInstall)
	mux.HandleFunc("POST /api/v1/service/uninstall", s.handleServiceUninstall)

	mux.HandleFunc("GET /api/v1/sse/logs/{name}", s.handleWSLogs)
	mux.HandleFunc("GET /api/v1/sse/events", s.handleWSEvents)

	mux.HandleFunc("GET /", s.handleStatic)

	s.httpServer.Handler = s.withMiddleware(mux)
}
