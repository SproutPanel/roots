package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/sproutpanel/roots/internal/api/handlers"
	"github.com/sproutpanel/roots/internal/config"
	"github.com/sproutpanel/roots/internal/docker"
	"github.com/sproutpanel/roots/internal/version"
)

// Server represents the API server
type Server struct {
	config       *config.Config
	configPath   string
	docker       *docker.Client
	router       *chi.Mux
	httpServer   *http.Server
	serverMgr    *handlers.ServerManager
	nodeMgr      *handlers.NodeManager
	backupMgr    *handlers.BackupManager
	logger       *slog.Logger
	startTime    time.Time
}

// NewServer creates a new API server
func NewServer(cfg *config.Config, configPath string, dockerClient *docker.Client, logger *slog.Logger) *Server {
	s := &Server{
		config:     cfg,
		configPath: configPath,
		docker:     dockerClient,
		logger:     logger,
		startTime:  time.Now(),
	}

	s.serverMgr = handlers.NewServerManager(dockerClient, cfg, logger)
	s.nodeMgr = handlers.NewNodeManager(cfg, dockerClient, logger)
	s.nodeMgr.SetServerManager(s.serverMgr)
	s.backupMgr = handlers.NewBackupManager(cfg, s.serverMgr, logger)
	s.setupRouter()

	return s
}

// ServerCount returns the number of loaded servers
func (s *Server) ServerCount() int {
	return s.serverMgr.ServerCount()
}

func (s *Server) setupRouter() {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(NewStructuredLogger(s.logger))
	r.Use(middleware.Recoverer)
	r.Use(TimeoutSkipWebSocket(60 * time.Second))

	// Auth middleware for all API routes
	r.Use(s.authMiddleware)

	// Health check (no auth required)
	r.Get("/health", s.handleHealth)

	// Status endpoint (requires auth)
	r.Get("/status", s.handleStatus)

	// Reload endpoint (requires auth)
	r.Post("/api/reload", s.handleReload)

	// API routes
	r.Route("/api", func(r chi.Router) {
		// Node stats and system info
		r.Get("/node/stats", s.nodeMgr.Stats)                           // WebSocket streaming
		r.Get("/node/status", s.nodeMgr.GetStats)                       // HTTP single request
		r.Get("/node/ips", s.nodeMgr.GetSystemIPs)                      // System IP addresses
		r.Delete("/node/docker/images/prune", s.nodeMgr.PruneDockerImages) // Prune unused Docker images

		// Server management
		r.Route("/servers", func(r chi.Router) {
			r.Post("/", s.serverMgr.Create)           // Create/install server
			r.Get("/", s.serverMgr.List)              // List all servers

			r.Route("/{uuid}", func(r chi.Router) {
				r.Get("/", s.serverMgr.Get)               // Get server status
				r.Put("/", s.serverMgr.Update)            // Update server settings
				r.Delete("/", s.serverMgr.Delete)         // Remove server
				r.Post("/power", s.serverMgr.Power)       // Power actions
				r.Post("/reinstall", s.serverMgr.Reinstall) // Reinstall server (preserves data)

				// Console WebSocket
				r.Get("/console", s.serverMgr.Console)

				// Stats WebSocket
				r.Get("/stats", s.serverMgr.Stats)

				// File operations (generic - all games)
				r.Route("/files", func(r chi.Router) {
					r.Get("/", s.serverMgr.ListFiles)              // List directory
					r.Get("/content", s.serverMgr.ReadFile)        // Read file
					r.Get("/download", s.serverMgr.DownloadFile)   // Download file
					r.Get("/search", s.serverMgr.SearchFiles)      // Search files
					r.Put("/content", s.serverMgr.WriteFile)       // Write file
					r.Delete("/", s.serverMgr.DeleteFile)          // Delete file/dir
					r.Post("/", s.serverMgr.CreateFile)            // Create file/dir
					r.Post("/rename", s.serverMgr.RenameFile)      // Rename file/dir
					r.Post("/move", s.serverMgr.MoveFile)          // Move file/dir
					r.Post("/copy", s.serverMgr.CopyFile)          // Copy file/dir
					r.Post("/chmod", s.serverMgr.ChmodFile)        // Change permissions
					r.Post("/compress", s.serverMgr.CompressFiles) // Compress files to zip
					r.Post("/decompress", s.serverMgr.DecompressFile) // Extract zip archive
				})

				// Backup operations (generic - all games)
				r.Route("/backups", func(r chi.Router) {
					r.Post("/", s.backupMgr.Create)              // Create backup
					r.Get("/", s.backupMgr.List)                 // List backups
					r.Get("/{backup_id}", s.backupMgr.Get)       // Get backup info
					r.Get("/{backup_id}/download", s.backupMgr.Download) // Download backup
					r.Delete("/{backup_id}", s.backupMgr.Delete) // Delete backup
					r.Post("/{backup_id}/restore", s.backupMgr.Restore) // Restore from backup
				})

				// Minecraft-specific routes
				// All Minecraft features are under /minecraft/ namespace
				r.Route("/minecraft", func(r chi.Router) {
					mcHandlers := s.serverMgr.GetMinecraftHandlers()
					mcHandlers.RegisterRoutes(r)

					// WebSocket for live player updates (needs ServerManager internals)
					r.Get("/players", s.serverMgr.Players)
				})

				// Hytale-specific routes
				r.Route("/hytale", func(r chi.Router) {
					r.Get("/version", s.serverMgr.GetHytaleVersion)
					r.Post("/update/check", s.serverMgr.CheckHytaleUpdate)
					r.Post("/update/apply", s.serverMgr.ApplyHytaleUpdate)

					// Hytale mod handlers
					hytaleHandlers := s.serverMgr.GetHytaleHandlers()
					hytaleHandlers.RegisterRoutes(r)
				})
			})
		})
	})

	s.router = r
}

// authMiddleware validates the panel token
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health check
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.URL.Query().Get("token") // Allow token in query for WebSocket
		}

		// Strip "Bearer " prefix if present
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		if token != s.config.Panel.Token {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleHealth returns the health status of the daemon
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check Docker connectivity
	if err := s.docker.Ping(ctx); err != nil {
		http.Error(w, "Docker unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"healthy","version":"` + version.Version + `"}`))
}

// StatusResponse contains detailed daemon status
type StatusResponse struct {
	Status         string `json:"status"`
	Version        string `json:"version"`
	Uptime         int64  `json:"uptime_seconds"`
	UptimeHuman    string `json:"uptime_human"`
	PanelURL       string `json:"panel_url"`
	ServersRunning int    `json:"servers_running"`
	ServersStopped int    `json:"servers_stopped"`
	DockerStatus   string `json:"docker_status"`
}

// handleStatus returns detailed status of the daemon
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check Docker connectivity
	dockerStatus := "connected"
	if err := s.docker.Ping(ctx); err != nil {
		dockerStatus = "disconnected"
	}

	// Get server counts
	running, stopped := s.serverMgr.ServerCounts()

	// Calculate uptime
	uptime := time.Since(s.startTime)

	response := StatusResponse{
		Status:         "healthy",
		Version:        version.Version,
		Uptime:         int64(uptime.Seconds()),
		UptimeHuman:    formatDuration(uptime),
		PanelURL:       s.config.Panel.URL,
		ServersRunning: running,
		ServersStopped: stopped,
		DockerStatus:   dockerStatus,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// formatDuration formats a duration as "Xd Xh Xm" or "Xs" for short durations
func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// Start starts the API server (HTTP or HTTPS depending on config)
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Daemon.Host, s.config.Daemon.Port)
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 5 * time.Minute, // Increased for large file downloads
		IdleTimeout:  120 * time.Second,
	}

	if s.config.TLSEnabled() {
		s.logger.Info("Starting API server with TLS", "address", addr)
		return s.httpServer.ListenAndServeTLS(s.config.TLSCertPath(), s.config.TLSKeyPath())
	}

	s.logger.Info("Starting API server", "address", addr)
	return s.httpServer.ListenAndServe()
}

// IsTLSEnabled returns whether TLS is enabled for the server
func (s *Server) IsTLSEnabled() bool {
	return s.config.TLSEnabled()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// SendHeartbeat sends a heartbeat to the panel to report the daemon is online
func (s *Server) SendHeartbeat() error {
	if s.config.Panel.URL == "" || s.config.Panel.Token == "" {
		s.logger.Debug("Skipping heartbeat - no panel configured")
		return nil
	}

	url := fmt.Sprintf("%s/api/internal/nodes/heartbeat", s.config.Panel.URL)
	payload := map[string]string{"version": version.Version}
	data, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create heartbeat request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.config.Panel.Token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send heartbeat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("heartbeat failed with status %d", resp.StatusCode)
	}

	s.logger.Info("Heartbeat sent to panel", "panel_url", s.config.Panel.URL)
	return nil
}

// NewStructuredLogger returns a chi middleware that logs requests
func NewStructuredLogger(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip logging for WebSocket endpoints to avoid hijack issues
			if isWebSocketRequest(r) {
				next.ServeHTTP(w, r)
				return
			}

			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			start := time.Now()

			defer func() {
				logger.Info("request",
					"method", r.Method,
					"path", r.URL.Path,
					"status", ww.Status(),
					"bytes", ww.BytesWritten(),
					"duration", time.Since(start),
					"remote", r.RemoteAddr,
				)
			}()

			next.ServeHTTP(ww, r)
		})
	}
}

// isWebSocketRequest checks if the request is a WebSocket upgrade
func isWebSocketRequest(r *http.Request) bool {
	return r.Header.Get("Upgrade") == "websocket"
}

// TimeoutSkipWebSocket returns a timeout middleware that skips WebSocket requests
func TimeoutSkipWebSocket(timeout time.Duration) func(next http.Handler) http.Handler {
	timeoutMiddleware := middleware.Timeout(timeout)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isWebSocketRequest(r) {
				next.ServeHTTP(w, r)
				return
			}
			timeoutMiddleware(next).ServeHTTP(w, r)
		})
	}
}

// handleReload reloads the configuration from disk
func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	newCfg, err := config.Load(s.configPath)
	if err != nil {
		s.logger.Error("Failed to reload config", "error", err)
		http.Error(w, fmt.Sprintf("Failed to reload config: %v", err), http.StatusInternalServerError)
		return
	}

	if err := newCfg.Validate(); err != nil {
		s.logger.Error("Config validation failed", "error", err)
		http.Error(w, fmt.Sprintf("Config validation failed: %v", err), http.StatusBadRequest)
		return
	}

	// Update the config
	s.config = newCfg

	// Update managers with new config
	s.serverMgr.UpdateConfig(newCfg)
	s.nodeMgr.UpdateConfig(newCfg)
	s.backupMgr.UpdateConfig(newCfg)

	s.logger.Info("Configuration reloaded")

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","message":"Configuration reloaded"}`))
}
