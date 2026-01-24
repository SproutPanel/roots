package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	dockerclient "github.com/docker/docker/client"
	"github.com/docker/docker/api/types/mount"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	"github.com/sproutpanel/roots/internal/config"
	"github.com/sproutpanel/roots/internal/docker"
	"github.com/sproutpanel/roots/internal/games"
	gameshytale "github.com/sproutpanel/roots/internal/games/hytale"
	"github.com/sproutpanel/roots/internal/games/minecraft"
	hthandlers "github.com/sproutpanel/roots/internal/games/hytale/handlers"
	mchandlers "github.com/sproutpanel/roots/internal/games/minecraft/handlers"
	"github.com/sproutpanel/roots/internal/hytale"
)

// ServerManager handles server-related API requests
type ServerManager struct {
	docker       *docker.Client
	config       *config.Config
	logger       *slog.Logger
	servers      map[string]*Server // in-memory server state
	mu           sync.RWMutex
	consoleConns map[string][]*websocket.Conn // active console connections per server UUID
	consoleMu    sync.Mutex
	mgmtConns    map[string]*minecraft.ManagementClient // persistent Management Protocol connections
	mgmtMu       sync.Mutex
	rconConns    map[string]*minecraft.RCONClient // persistent RCON connections
	rconMu       sync.Mutex
}

// Server represents a managed game server
type Server struct {
	UUID        string            `json:"uuid"`
	PublicID    string            `json:"public_id,omitempty"`
	Slug        string            `json:"slug,omitempty"`
	Name        string            `json:"name"`
	GameType    games.GameType    `json:"game_type"`  // minecraft, hytale, etc.
	Status      string            `json:"status"`     // installing, offline, starting, online, stopping, crashed
	ContainerID string            `json:"container_id,omitempty"`
	Image       string            `json:"image"`
	Env         map[string]string `json:"env"`
	Memory      int64             `json:"memory"`      // bytes
	DiskLimit   int64             `json:"disk_limit"`  // bytes (0 = unlimited)
	CPU         int64             `json:"cpu"`         // millicores
	Ports       map[int]int       `json:"ports"`       // container -> host
	StartupCmd  []string          `json:"startup_cmd"`
	Version     string            `json:"version,omitempty"` // Game version (e.g., "1.21.9", "latest")
	CreatedAt   time.Time         `json:"created_at"`
}

// NewServerManager creates a new server manager
func NewServerManager(docker *docker.Client, cfg *config.Config, logger *slog.Logger) *ServerManager {
	sm := &ServerManager{
		docker:       docker,
		config:       cfg,
		logger:       logger,
		servers:      make(map[string]*Server),
		consoleConns: make(map[string][]*websocket.Conn),
		mgmtConns:    make(map[string]*minecraft.ManagementClient),
		rconConns:    make(map[string]*minecraft.RCONClient),
	}

	// Load existing servers from disk
	sm.loadServers()

	// Sync container states
	go sm.syncContainerStates()

	return sm
}

// loadServers loads server metadata from disk
func (sm *ServerManager) loadServers() {
	sm.logger.Info("loading servers with game_type migration support")
	serversDir := sm.config.Storage.Servers
	entries, err := os.ReadDir(serversDir)
	if err != nil {
		if !os.IsNotExist(err) {
			sm.logger.Error("failed to read servers directory", "error", err)
		}
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		metaPath := filepath.Join(serversDir, entry.Name(), ".roots", "server.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}

		var server Server
		if err := json.Unmarshal(data, &server); err != nil {
			sm.logger.Error("failed to parse server metadata", "uuid", entry.Name(), "error", err)
			continue
		}

		// Normalize game_type for legacy servers (default to minecraft)
		sm.logger.Debug("loaded server game_type", "uuid", server.UUID, "game_type", server.GameType, "is_empty", server.GameType == "")
		if server.GameType == "" {
			server.GameType = games.GameMinecraft
			sm.logger.Info("migrating legacy server to minecraft game_type", "uuid", server.UUID, "new_game_type", server.GameType)
			// Persist the fix so it only needs to happen once
			if err := sm.saveServer(&server); err != nil {
				sm.logger.Error("failed to save migrated server", "uuid", server.UUID, "error", err)
			} else {
				sm.logger.Info("successfully saved migrated server", "uuid", server.UUID)
			}
		}

		sm.servers[server.UUID] = &server
		sm.logger.Info("loaded server", "uuid", server.UUID, "name", server.Name)
	}
}

// syncContainerStates syncs container states with Docker
func (sm *ServerManager) syncContainerStates() {
	ctx := context.Background()

	containers, err := sm.docker.ListManagedContainers(ctx)
	if err != nil {
		sm.logger.Error("failed to list containers", "error", err)
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, c := range containers {
		uuid := c.Labels["roots.server.uuid"]
		if server, ok := sm.servers[uuid]; ok {
			server.ContainerID = c.ID
			server.Status = containerStateToStatus(c.State)
		}
	}
}

func containerStateToStatus(state string) string {
	switch state {
	case "running":
		return "online"
	case "created", "exited", "dead":
		return "offline"
	case "restarting":
		return "starting"
	case "paused":
		return "stopping"
	default:
		return "offline"
	}
}

// saveServer persists server metadata to disk
func (sm *ServerManager) saveServer(server *Server) error {
	serverDir := filepath.Join(sm.config.Storage.Servers, server.UUID)
	metaDir := filepath.Join(serverDir, ".roots")

	if err := os.MkdirAll(metaDir, 0755); err != nil {
		return fmt.Errorf("failed to create metadata directory: %w", err)
	}

	data, err := json.MarshalIndent(server, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal server: %w", err)
	}

	metaPath := filepath.Join(metaDir, "server.json")
	if err := os.WriteFile(metaPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write server metadata: %w", err)
	}

	return nil
}

// reportStatusToPanel sends a status update to the panel
func (sm *ServerManager) reportStatusToPanel(serverUUID, status string, errorMsg ...string) {
	if sm.config.Panel.URL == "" || sm.config.Panel.Token == "" {
		sm.logger.Debug("skipping panel callback - no panel configured")
		return
	}

	url := fmt.Sprintf("%s/api/internal/servers/%s/status", sm.config.Panel.URL, serverUUID)
	payload := map[string]string{"status": status}
	if len(errorMsg) > 0 && errorMsg[0] != "" {
		payload["error"] = errorMsg[0]
	}
	data, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		sm.logger.Error("failed to create panel callback request", "error", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+sm.config.Panel.Token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		sm.logger.Error("failed to send panel callback", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		sm.logger.Error("panel callback failed", "status", resp.StatusCode, "server", serverUUID)
	} else {
		sm.logger.Info("panel callback sent", "server", serverUUID, "status", status)
	}
}

// CreateRequest is the request body for creating a server
type CreateRequest struct {
	UUID        string            `json:"uuid"`
	PublicID    string            `json:"public_id"`
	Slug        string            `json:"slug"`
	Name        string            `json:"name"`
	GameType    games.GameType    `json:"game_type"` // minecraft, hytale, etc. (defaults to minecraft)
	Image       string            `json:"image"`
	StartupCmd  string            `json:"startup_cmd"`
	Env         map[string]string `json:"env"`
	Memory      int64             `json:"memory"` // MB
	CPU         int               `json:"cpu"`    // percent (100 = 1 core)
	Disk        int64             `json:"disk"`   // MB
	Ports       map[int]int       `json:"ports"`
	Version     string            `json:"version,omitempty"` // Game version (e.g., "1.21.9", "latest")
	Installation *InstallationConfig `json:"installation,omitempty"`
}

// InstallationConfig defines how to install a server
type InstallationConfig struct {
	Script     string `json:"script"`
	Container  string `json:"container"`
	Entrypoint string `json:"entrypoint"`
}

// Create handles POST /api/servers
func (sm *ServerManager) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate
	if req.UUID == "" || req.Name == "" || req.Image == "" {
		http.Error(w, "uuid, name, and image are required", http.StatusBadRequest)
		return
	}

	// Default game type to minecraft if not provided
	gameType := req.GameType
	if gameType == "" {
		gameType = games.GameMinecraft
	}
	if !gameType.IsValid() {
		http.Error(w, "invalid game_type", http.StatusBadRequest)
		return
	}

	sm.mu.Lock()
	if _, exists := sm.servers[req.UUID]; exists {
		sm.mu.Unlock()
		http.Error(w, "Server already exists", http.StatusConflict)
		return
	}
	sm.mu.Unlock()

	// Create server directory
	serverDir := filepath.Join(sm.config.Storage.Servers, req.UUID)
	if err := os.MkdirAll(serverDir, 0755); err != nil {
		sm.logger.Error("failed to create server directory", "error", err)
		http.Error(w, "Failed to create server directory", http.StatusInternalServerError)
		return
	}

	// Set ownership to the UID that the server image runs as
	uid, gid := sm.docker.GetImageUID(r.Context(), req.Image)
	sm.logger.Info("detected container UID", "image", req.Image, "uid", uid, "gid", gid)
	if err := os.Chown(serverDir, uid, gid); err != nil {
		sm.logger.Warn("failed to chown server directory", "error", err)
		// Continue anyway - might work if running as same user
	}

	// Parse startup command
	startupCmd := parseCommand(req.StartupCmd)

	// Create server record
	server := &Server{
		UUID:       req.UUID,
		PublicID:   req.PublicID,
		Slug:       req.Slug,
		Name:       req.Name,
		GameType:   gameType,
		Status:     "installing",
		Image:      req.Image,
		Env:        req.Env,
		Memory:     req.Memory * 1024 * 1024, // Convert MB to bytes
		DiskLimit:  req.Disk * 1024 * 1024,   // Convert MB to bytes
		CPU:        int64(req.CPU) * 10,      // Convert percent to millicores
		Ports:      req.Ports,
		StartupCmd: startupCmd,
		Version:    req.Version,
		CreatedAt:  time.Now(),
	}

	sm.mu.Lock()
	sm.servers[req.UUID] = server
	sm.mu.Unlock()

	// Save metadata
	if err := sm.saveServer(server); err != nil {
		sm.logger.Error("failed to save server", "error", err)
	}

	// Run installation if provided
	if req.Installation != nil && req.Installation.Script != "" {
		go sm.runInstallation(server, req.Installation, serverDir)
	} else {
		server.Status = "offline"
		sm.saveServer(server)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(server)
}

// runInstallation runs the server installation script
func (sm *ServerManager) runInstallation(server *Server, install *InstallationConfig, serverDir string) {
	ctx := context.Background()

	sm.logger.Info("starting installation", "uuid", server.UUID, "name", server.Name, "game_type", server.GameType)

	// Helper to set failed status and report with error
	setFailed := func(errMsg string) {
		server.Status = "install_failed"
		sm.saveServer(server)
		sm.reportStatusToPanel(server.UUID, "install_failed", errMsg)
	}

	// Hytale servers use the hytale-downloader instead of a script
	if server.GameType == games.GameHytale {
		sm.runHytaleInstallation(ctx, server, serverDir, setFailed)
		return
	}

	// Pull installation image
	if !sm.docker.ImageExists(ctx, install.Container) {
		sm.logger.Info("pulling installation image", "image", install.Container)
		if err := sm.docker.PullImage(ctx, install.Container); err != nil {
			sm.logger.Error("failed to pull installation image", "error", err)
			setFailed(fmt.Sprintf("Failed to pull installation image: %v", err))
			return
		}
	}

	// Write installation script
	scriptPath := filepath.Join(serverDir, ".roots", "install.sh")
	if err := os.WriteFile(scriptPath, []byte(install.Script), 0755); err != nil {
		sm.logger.Error("failed to write install script", "error", err)
		setFailed(fmt.Sprintf("Failed to write install script: %v", err))
		return
	}

	// Create and run installation container
	cfg := &docker.ServerConfig{
		UUID:        server.UUID + "-install",
		Name:        fmt.Sprintf("roots-install-%s", server.UUID[:8]),
		Image:       install.Container,
		Cmd:         []string{install.Entrypoint, "/mnt/server/.roots/install.sh"},
		Env:         server.Env,
		MemoryLimit: 1024 * 1024 * 1024, // 1GB for installation
		CPULimit:    2000,               // 2 cores
		ServerDir:   serverDir,
		MountTarget: "/mnt/server",      // Installation scripts expect /mnt/server
		WorkingDir:  "/mnt/server",
	}

	containerID, err := sm.docker.CreateContainer(ctx, cfg)
	if err != nil {
		sm.logger.Error("failed to create installation container", "error", err)
		setFailed(fmt.Sprintf("Failed to create installation container: %v", err))
		return
	}

	defer sm.docker.RemoveContainer(ctx, containerID, true)

	if err := sm.docker.StartContainer(ctx, containerID); err != nil {
		sm.logger.Error("failed to start installation container", "error", err)
		setFailed(fmt.Sprintf("Failed to start installation container: %v", err))
		return
	}

	// Wait for installation to complete (with timeout)
	timeout := time.After(10 * time.Minute)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			sm.logger.Error("installation timed out", "uuid", server.UUID)
			sm.docker.KillContainer(ctx, containerID)
			setFailed("Installation timed out after 10 minutes")
			return
		case <-ticker.C:
			status, err := sm.docker.GetContainerStatus(ctx, containerID)
			if err != nil {
				continue
			}

			if !status.Running {
				if status.ExitCode == 0 {
					sm.logger.Info("installation completed", "uuid", server.UUID)

					// Game-specific post-installation configuration
					switch server.GameType {
					case games.GameMinecraft:
						// Auto-configure RCON for Minecraft servers
						if rconCfg, err := minecraft.ConfigureRCON(serverDir, 25575, ""); err != nil {
							sm.logger.Warn("failed to auto-configure RCON", "uuid", server.UUID, "error", err)
						} else {
							sm.logger.Info("auto-configured RCON", "uuid", server.UUID, "port", rconCfg.Port)
						}

						// Auto-configure Management Protocol for Minecraft 1.21.9+ servers
						// Check Version field first, then fall back to environment variables
						version := server.Version
						if version == "" {
							version = getVersionFromEnv(server.Env)
						}
						if minecraft.SupportsManagementProtocol(version) {
							if mgmtCfg, err := minecraft.ConfigureManagement(serverDir, 25576, ""); err != nil {
								sm.logger.Warn("failed to auto-configure Management Protocol", "uuid", server.UUID, "error", err)
							} else {
								sm.logger.Info("auto-configured Management Protocol", "uuid", server.UUID, "port", mgmtCfg.Port, "version", version)
							}
						}

					case games.GameHytale:
						// Hytale post-installation: nothing special needed yet
						// The hytale-downloader handles server file downloads
						// Server auth happens at runtime via /auth login device
						sm.logger.Info("Hytale server installation completed", "uuid", server.UUID)
					}

					// Fix ownership of all files created during installation
					// Install containers run as root, but server containers run as their configured user
					// This must run AFTER post-installation configuration to catch all files
					uid, gid := sm.docker.GetImageUID(ctx, server.Image)
					sm.logger.Info("chowning server directory", "uuid", server.UUID, "uid", uid, "gid", gid)
					if err := chownRecursive(serverDir, uid, gid); err != nil {
						sm.logger.Warn("failed to chown server directory after install", "error", err)
					}

					server.Status = "offline"
					sm.saveServer(server)
					sm.reportStatusToPanel(server.UUID, "offline")
				} else {
					sm.logger.Error("installation failed", "uuid", server.UUID, "exit_code", status.ExitCode)
					setFailed(fmt.Sprintf("Installation script failed with exit code %d", status.ExitCode))
				}
				return
			}
		}
	}
}

// List handles GET /api/servers
func (sm *ServerManager) List(w http.ResponseWriter, r *http.Request) {
	sm.mu.RLock()
	servers := make([]*Server, 0, len(sm.servers))
	for _, s := range sm.servers {
		servers = append(servers, s)
	}
	sm.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(servers)
}

// ServerCount returns the total number of servers
func (sm *ServerManager) ServerCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.servers)
}

// ServerCounts returns counts of servers by status
func (sm *ServerManager) ServerCounts() (running int, stopped int) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	for _, s := range sm.servers {
		if s.Status == "online" {
			running++
		} else {
			stopped++
		}
	}
	return
}

// UpdateConfig updates the manager's configuration
func (sm *ServerManager) UpdateConfig(cfg *config.Config) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.config = cfg
}

// registerConsoleConn adds a console connection for tracking
func (sm *ServerManager) registerConsoleConn(uuid string, conn *websocket.Conn) {
	sm.consoleMu.Lock()
	defer sm.consoleMu.Unlock()
	sm.consoleConns[uuid] = append(sm.consoleConns[uuid], conn)
}

// unregisterConsoleConn removes a console connection from tracking
func (sm *ServerManager) unregisterConsoleConn(uuid string, conn *websocket.Conn) {
	sm.consoleMu.Lock()
	defer sm.consoleMu.Unlock()
	conns := sm.consoleConns[uuid]
	for i, c := range conns {
		if c == conn {
			sm.consoleConns[uuid] = append(conns[:i], conns[i+1:]...)
			break
		}
	}
}

// closeConsoleConns closes all console connections for a server
func (sm *ServerManager) closeConsoleConns(uuid string) {
	sm.consoleMu.Lock()
	conns := sm.consoleConns[uuid]
	delete(sm.consoleConns, uuid)
	sm.consoleMu.Unlock()

	for _, conn := range conns {
		conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Server stopped"))
		conn.Close()
	}
}

// Get handles GET /api/servers/{uuid}
func (sm *ServerManager) Get(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	sm.mu.RLock()
	server, ok := sm.servers[uuid]
	sm.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Get live container status
	if server.ContainerID != "" {
		ctx := r.Context()
		status, err := sm.docker.GetContainerStatus(ctx, server.ContainerID)
		if err == nil {
			server.Status = containerStateToStatus(status.Status)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(server)
}

// Delete handles DELETE /api/servers/{uuid}
func (sm *ServerManager) Delete(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	sm.mu.Lock()
	server, ok := sm.servers[uuid]
	if !ok {
		sm.mu.Unlock()
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}
	delete(sm.servers, uuid)
	sm.mu.Unlock()

	ctx := r.Context()

	// Stop and remove container if exists
	if server.ContainerID != "" {
		sm.docker.StopContainer(ctx, server.ContainerID, 10)
		sm.docker.RemoveContainer(ctx, server.ContainerID, true)
	}

	// Remove server directory
	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)
	if err := os.RemoveAll(serverDir); err != nil {
		sm.logger.Error("failed to remove server directory", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

// UpdateRequest is the request body for updating a server
type UpdateRequest struct {
	PublicID   string            `json:"public_id,omitempty"`
	Slug       string            `json:"slug,omitempty"`
	Name       string            `json:"name,omitempty"`
	Memory     int64             `json:"memory,omitempty"`     // MB
	CPU        int               `json:"cpu,omitempty"`        // percent (100 = 1 core)
	Disk       int64             `json:"disk,omitempty"`       // MB
	Env        map[string]string `json:"env,omitempty"`
	StartupCmd string            `json:"startup_cmd,omitempty"`
	Ports      map[int]int       `json:"ports,omitempty"`      // container -> host port mappings
}

// Update handles PUT /api/servers/{uuid}
func (sm *ServerManager) Update(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	var req UpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	sm.mu.Lock()
	server, ok := sm.servers[uuid]
	if !ok {
		sm.mu.Unlock()
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Track if resource limits changed (requires container update)
	resourcesChanged := false
	oldMemory := server.Memory
	oldCPU := server.CPU

	// Update fields if provided
	if req.PublicID != "" {
		server.PublicID = req.PublicID
	}
	if req.Slug != "" {
		server.Slug = req.Slug
	}
	if req.Name != "" {
		server.Name = req.Name
	}
	if req.Memory > 0 {
		newMemory := req.Memory * 1024 * 1024 // Convert MB to bytes
		if newMemory != server.Memory {
			server.Memory = newMemory
			resourcesChanged = true
		}
	}
	if req.CPU > 0 {
		newCPU := int64(req.CPU) * 10 // Convert percent to millicores
		if newCPU != server.CPU {
			server.CPU = newCPU
			resourcesChanged = true
		}
	}
	if req.Disk > 0 {
		server.DiskLimit = req.Disk * 1024 * 1024 // Convert MB to bytes
	}
	if req.Env != nil {
		server.Env = req.Env
	}
	if req.StartupCmd != "" {
		server.StartupCmd = parseCommand(req.StartupCmd)
	}

	// Track if ports changed (requires container recreation on next restart)
	portsChanged := false
	if req.Ports != nil {
		// Check if ports actually changed
		if !portsEqual(server.Ports, req.Ports) {
			server.Ports = req.Ports
			portsChanged = true
		}
	}

	sm.mu.Unlock()

	// Save updated metadata
	if err := sm.saveServer(server); err != nil {
		sm.logger.Error("failed to save server", "error", err)
		http.Error(w, "Failed to save server", http.StatusInternalServerError)
		return
	}

	// If resource limits changed and container is running, update container resources
	if resourcesChanged && server.ContainerID != "" && server.Status == "online" {
		ctx := r.Context()
		if err := sm.docker.UpdateContainerResources(ctx, server.ContainerID, server.Memory, server.CPU); err != nil {
			sm.logger.Warn("failed to update container resources, will apply on next restart",
				"error", err,
				"uuid", uuid,
				"old_memory", oldMemory,
				"new_memory", server.Memory,
				"old_cpu", oldCPU,
				"new_cpu", server.CPU,
			)
		} else {
			sm.logger.Info("updated container resources",
				"uuid", uuid,
				"memory", server.Memory,
				"cpu", server.CPU,
			)
		}
	}

	// Log port changes (will apply on next restart)
	if portsChanged {
		sm.logger.Info("port mappings updated, will apply on next restart",
			"uuid", uuid,
			"ports", server.Ports,
		)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(server)
}

// PowerRequest is the request body for power actions
type PowerRequest struct {
	Action string `json:"action"` // start, stop, restart, kill
}

// ReinstallRequest is the request body for reinstalling a server
type ReinstallRequest struct {
	Installation *InstallationConfig `json:"installation"`
}

// Power handles POST /api/servers/{uuid}/power
func (sm *ServerManager) Power(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	var req PowerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	sm.mu.Lock()
	server, ok := sm.servers[uuid]
	sm.mu.Unlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	ctx := r.Context()
	var err error

	switch req.Action {
	case "start":
		err = sm.startServer(ctx, server)
	case "stop":
		err = sm.stopServer(ctx, server)
	case "restart":
		if err = sm.stopServer(ctx, server); err == nil {
			time.Sleep(1 * time.Second)
			err = sm.startServer(ctx, server)
		}
	case "kill":
		err = sm.killServer(ctx, server)
	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	if err != nil {
		sm.logger.Error("power action failed", "action", req.Action, "uuid", uuid, "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sm.saveServer(server)

	// Report status change to panel
	go sm.reportStatusToPanel(server.UUID, server.Status)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(server)
}

// Reinstall handles POST /api/servers/{uuid}/reinstall
// Re-runs the installation script in the existing server directory WITHOUT deleting server data.
// This allows updating server software (jar files) while preserving worlds, plugins, and configs.
func (sm *ServerManager) Reinstall(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	var req ReinstallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Installation == nil || req.Installation.Script == "" {
		http.Error(w, "installation.script is required", http.StatusBadRequest)
		return
	}

	sm.mu.Lock()
	server, ok := sm.servers[uuid]
	if !ok {
		sm.mu.Unlock()
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Server must be offline to reinstall
	if server.Status != "offline" && server.Status != "install_failed" && server.Status != "crashed" {
		sm.mu.Unlock()
		http.Error(w, "Server must be offline, crashed, or failed to reinstall", http.StatusBadRequest)
		return
	}

	// Update status to installing
	server.Status = "installing"
	sm.mu.Unlock()

	// Save status immediately
	sm.saveServer(server)

	// Report status to panel
	go sm.reportStatusToPanel(server.UUID, "installing")

	serverDir := filepath.Join(sm.config.Storage.Servers, server.UUID)

	// Run installation in background (same as initial install, but in existing directory)
	go sm.runReinstallation(server, req.Installation, serverDir)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "installing",
		"message": "Reinstallation started",
	})
}

// runReinstallation runs the installation script in an existing server directory
// This preserves existing data while updating/reinstalling server software
func (sm *ServerManager) runReinstallation(server *Server, install *InstallationConfig, serverDir string) {
	ctx := context.Background()

	sm.logger.Info("starting reinstallation", "uuid", server.UUID, "name", server.Name)

	// Helper to set failed status and report with error
	setFailed := func(errMsg string) {
		server.Status = "install_failed"
		sm.saveServer(server)
		sm.reportStatusToPanel(server.UUID, "install_failed", errMsg)
	}

	// Hytale servers use the hytale-downloader instead of a script
	if server.GameType == games.GameHytale {
		sm.runHytaleInstallation(ctx, server, serverDir, setFailed)
		return
	}

	// Pull installation image
	if !sm.docker.ImageExists(ctx, install.Container) {
		sm.logger.Info("pulling installation image", "image", install.Container)
		if err := sm.docker.PullImage(ctx, install.Container); err != nil {
			sm.logger.Error("failed to pull installation image", "error", err)
			setFailed(fmt.Sprintf("Failed to pull installation image: %v", err))
			return
		}
	}

	// Ensure .roots directory exists
	rootsDir := filepath.Join(serverDir, ".roots")
	if err := os.MkdirAll(rootsDir, 0755); err != nil {
		sm.logger.Error("failed to create .roots directory", "error", err)
		setFailed(fmt.Sprintf("Failed to create .roots directory: %v", err))
		return
	}

	// Write installation script (overwrites previous)
	scriptPath := filepath.Join(rootsDir, "install.sh")
	if err := os.WriteFile(scriptPath, []byte(install.Script), 0755); err != nil {
		sm.logger.Error("failed to write install script", "error", err)
		setFailed(fmt.Sprintf("Failed to write install script: %v", err))
		return
	}

	// Create and run installation container
	cfg := &docker.ServerConfig{
		UUID:        server.UUID + "-reinstall",
		Name:        fmt.Sprintf("roots-reinstall-%s", server.UUID[:8]),
		Image:       install.Container,
		Cmd:         []string{install.Entrypoint, "/mnt/server/.roots/install.sh"},
		Env:         server.Env,
		MemoryLimit: 1024 * 1024 * 1024, // 1GB for installation
		CPULimit:    2000,               // 2 cores
		ServerDir:   serverDir,
		MountTarget: "/mnt/server", // Installation scripts expect /mnt/server
		WorkingDir:  "/mnt/server",
	}

	containerID, err := sm.docker.CreateContainer(ctx, cfg)
	if err != nil {
		sm.logger.Error("failed to create reinstallation container", "error", err)
		setFailed(fmt.Sprintf("Failed to create reinstallation container: %v", err))
		return
	}

	defer sm.docker.RemoveContainer(ctx, containerID, true)

	if err := sm.docker.StartContainer(ctx, containerID); err != nil {
		sm.logger.Error("failed to start reinstallation container", "error", err)
		setFailed(fmt.Sprintf("Failed to start reinstallation container: %v", err))
		return
	}

	// Wait for installation to complete (with timeout)
	timeout := time.After(10 * time.Minute)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			sm.logger.Error("reinstallation timed out", "uuid", server.UUID)
			sm.docker.KillContainer(ctx, containerID)
			setFailed("Reinstallation timed out after 10 minutes")
			return
		case <-ticker.C:
			status, err := sm.docker.GetContainerStatus(ctx, containerID)
			if err != nil {
				continue
			}

			if !status.Running {
				if status.ExitCode == 0 {
					sm.logger.Info("reinstallation completed", "uuid", server.UUID)

					// Game-specific post-reinstallation configuration
					switch server.GameType {
					case games.GameMinecraft:
						// Re-configure RCON for Minecraft servers
						if rconCfg, err := minecraft.ConfigureRCON(serverDir, 25575, ""); err != nil {
							sm.logger.Warn("failed to re-configure RCON", "uuid", server.UUID, "error", err)
						} else {
							sm.logger.Info("re-configured RCON", "uuid", server.UUID, "port", rconCfg.Port)
						}

						// Re-configure Management Protocol for Minecraft 1.21.9+ servers
						version := server.Version
						if version == "" {
							version = getVersionFromEnv(server.Env)
						}
						if minecraft.SupportsManagementProtocol(version) {
							if mgmtCfg, err := minecraft.ConfigureManagement(serverDir, 25576, ""); err != nil {
								sm.logger.Warn("failed to re-configure Management Protocol", "uuid", server.UUID, "error", err)
							} else {
								sm.logger.Info("re-configured Management Protocol", "uuid", server.UUID, "port", mgmtCfg.Port, "version", version)
							}
						}

					case games.GameHytale:
						// Hytale reinstallation: nothing special needed
						sm.logger.Info("Hytale server reinstallation completed", "uuid", server.UUID)
					}

					// Fix ownership of all files created during reinstallation
					// Install containers run as root, but server containers run as their configured user
					// This must run AFTER post-reinstallation configuration to catch all files
					uid, gid := sm.docker.GetImageUID(ctx, server.Image)
					sm.logger.Info("chowning server directory", "uuid", server.UUID, "uid", uid, "gid", gid)
					if err := chownRecursive(serverDir, uid, gid); err != nil {
						sm.logger.Warn("failed to chown server directory after reinstall", "error", err)
					}

					server.Status = "offline"
					sm.saveServer(server)
					sm.reportStatusToPanel(server.UUID, "offline")
				} else {
					sm.logger.Error("reinstallation failed", "uuid", server.UUID, "exit_code", status.ExitCode)
					setFailed(fmt.Sprintf("Reinstallation script failed with exit code %d", status.ExitCode))
				}
				return
			}
		}
	}
}

// runHytaleInstallation uses the hytale-downloader to install Hytale server files
func (sm *ServerManager) runHytaleInstallation(ctx context.Context, server *Server, serverDir string, setFailed func(string)) {
	sm.logger.Info("starting Hytale installation via downloader", "uuid", server.UUID)

	// Get patchline from environment (default: "release")
	patchline := server.Env["HYTALE_PATCHLINE"]
	if patchline == "" {
		patchline = "release"
	}

	// Create a Docker client for the downloader
	// The downloader wrapper uses its own Docker client instance
	dockerClient, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		sm.logger.Error("failed to create Docker client for Hytale downloader", "error", err)
		setFailed(fmt.Sprintf("Failed to create Docker client: %v", err))
		return
	}
	defer dockerClient.Close()

	// Create the downloader client
	downloader := hytale.NewDownloaderClient(dockerClient, sm.logger)

	// Output callback - broadcasts to console WebSocket and detects auth prompts
	callback := func(line string, event *gameshytale.ConsoleEvent) {
		// Log the output
		sm.logger.Debug("Hytale downloader output", "uuid", server.UUID, "line", line)

		// Broadcast to any connected console WebSocket clients
		sm.broadcastToConsole(server.UUID, line)

		// Handle auth prompt events
		if event != nil && event.Type == gameshytale.EventAuthPrompt {
			sm.logger.Info("Hytale auth required",
				"uuid", server.UUID,
				"url", event.URL,
				"code", event.Code,
			)
			// Broadcast auth event to panel
			sm.broadcastHytaleAuthEvent(server.UUID, event.URL, event.Code, "downloader")
		}
	}

	// Run the downloader
	result, err := downloader.DownloadServer(ctx, serverDir, patchline, callback)
	if err != nil {
		sm.logger.Error("Hytale download failed", "uuid", server.UUID, "error", err)
		setFailed(fmt.Sprintf("Hytale download failed: %v", err))
		return
	}

	if !result.Success {
		sm.logger.Error("Hytale download unsuccessful", "uuid", server.UUID, "error", result.Error)
		setFailed(fmt.Sprintf("Hytale download failed: %s", result.Error))
		return
	}

	// Save the installed version
	if result.Version != "" {
		server.Version = result.Version
		if err := downloader.SaveInstalledVersion(serverDir, result.Version); err != nil {
			sm.logger.Warn("failed to save Hytale version marker", "uuid", server.UUID, "error", err)
		}
	}

	sm.logger.Info("Hytale installation completed", "uuid", server.UUID, "version", result.Version)

	server.Status = "offline"
	sm.saveServer(server)
	sm.reportStatusToPanel(server.UUID, "offline")
}

// broadcastToConsole sends a message to all connected console WebSocket clients
func (sm *ServerManager) broadcastToConsole(uuid string, message string) {
	sm.consoleMu.Lock()
	conns := sm.consoleConns[uuid]
	sm.consoleMu.Unlock()

	for _, conn := range conns {
		conn.WriteMessage(websocket.TextMessage, []byte(message+"\n"))
	}
}

// broadcastHytaleAuthEvent sends a Hytale auth prompt event to the panel
// This is used when the hytale-downloader or server outputs a device code
func (sm *ServerManager) broadcastHytaleAuthEvent(serverUUID, url, code, context string) {
	// Send to panel via callback endpoint
	if sm.config.Panel.URL == "" || sm.config.Panel.Token == "" {
		sm.logger.Debug("skipping Hytale auth event - no panel configured")
		return
	}

	callbackURL := fmt.Sprintf("%s/api/internal/servers/%s/hytale/auth_event", sm.config.Panel.URL, serverUUID)
	payload := map[string]string{
		"event":   "auth_required",
		"url":     url,
		"code":    code,
		"context": context, // "downloader" or "server"
	}
	data, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", callbackURL, bytes.NewReader(data))
	if err != nil {
		sm.logger.Error("failed to create Hytale auth event request", "error", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+sm.config.Panel.Token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		sm.logger.Error("failed to send Hytale auth event", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		sm.logger.Error("Hytale auth event callback failed", "status", resp.StatusCode, "server", serverUUID)
	} else {
		sm.logger.Info("Hytale auth event sent to panel", "server", serverUUID, "code", code)
	}
}

// checkAndApplyHytaleUpdate checks for Hytale updates and applies them if available
func (sm *ServerManager) checkAndApplyHytaleUpdate(ctx context.Context, server *Server, serverDir string) error {
	// Create a Docker client for the downloader
	dockerClient, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer dockerClient.Close()

	downloader := hytale.NewDownloaderClient(dockerClient, sm.logger)

	// Get the patchline from environment
	patchline := server.Env["HYTALE_PATCHLINE"]
	if patchline == "" {
		patchline = "release"
	}

	// Callback for output and auth detection
	callback := func(line string, event *gameshytale.ConsoleEvent) {
		sm.logger.Debug("Hytale update output", "uuid", server.UUID, "line", line)
		sm.broadcastToConsole(server.UUID, line)

		if event != nil && event.Type == gameshytale.EventAuthPrompt {
			sm.logger.Info("Hytale auth required during update",
				"uuid", server.UUID,
				"url", event.URL,
				"code", event.Code,
			)
			sm.broadcastHytaleAuthEvent(server.UUID, event.URL, event.Code, "downloader")
		}
	}

	// Check if we have an installed version - if not, we need to download
	installedVersion, _ := downloader.GetInstalledVersion(serverDir)

	// If we have an installed version, check if an update is available first
	if installedVersion != "" {
		sm.logger.Info("Checking for Hytale updates", "uuid", server.UUID, "installed_version", installedVersion)
		sm.broadcastToConsole(server.UUID, fmt.Sprintf("Checking for updates (current: %s)...", installedVersion))

		updateAvailable, latestVersion, err := downloader.CheckUpdate(ctx, serverDir, callback)
		if err != nil {
			sm.logger.Warn("Failed to check for Hytale updates", "uuid", server.UUID, "error", err)
			sm.broadcastToConsole(server.UUID, "Update check failed, continuing with current version")
			return nil // Non-fatal, continue with current version
		}

		if !updateAvailable {
			sm.logger.Info("Hytale server is up to date", "uuid", server.UUID, "version", installedVersion)
			sm.broadcastToConsole(server.UUID, fmt.Sprintf("Server is up to date (version: %s)", installedVersion))
			return nil
		}

		sm.logger.Info("Hytale update available", "uuid", server.UUID, "current", installedVersion, "latest", latestVersion)
		sm.broadcastToConsole(server.UUID, fmt.Sprintf("Update available: %s -> %s", installedVersion, latestVersion))
	} else {
		sm.logger.Info("No installed version found, downloading Hytale server", "uuid", server.UUID)
		sm.broadcastToConsole(server.UUID, "Downloading Hytale server files...")
	}

	// Download the server files
	result, err := downloader.DownloadServer(ctx, serverDir, patchline, callback)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("download failed: %s", result.Error)
	}

	// Update version if changed
	if result.Version != "" && result.Version != server.Version {
		sm.logger.Info("Hytale server updated",
			"uuid", server.UUID,
			"old_version", server.Version,
			"new_version", result.Version,
		)
		server.Version = result.Version
		if err := downloader.SaveInstalledVersion(serverDir, result.Version); err != nil {
			sm.logger.Warn("failed to save Hytale version marker", "uuid", server.UUID, "error", err)
		}
		sm.saveServer(server)
	}

	return nil
}

func (sm *ServerManager) startServer(ctx context.Context, server *Server) error {
	// For Hytale servers, use a longer timeout since update checks require Docker operations
	if server.GameType == games.GameHytale {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
	}

	// Pull image if needed
	if !sm.docker.ImageExists(ctx, server.Image) {
		sm.logger.Info("pulling server image", "image", server.Image)
		if err := sm.docker.PullImage(ctx, server.Image); err != nil {
			return fmt.Errorf("failed to pull image: %w", err)
		}
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, server.UUID)

	// Hytale auto-update on start
	if server.GameType == games.GameHytale {
		serverJar := filepath.Join(serverDir, "Server", "HytaleServer.jar")
		autoUpdate := server.Env["HYTALE_AUTO_UPDATE"]
		autoUpdateEnabled := autoUpdate == "" || autoUpdate == "true" || autoUpdate == "1"

		// Check if server files exist first
		if _, statErr := os.Stat(serverJar); os.IsNotExist(statErr) {
			// No server files - need to download (blocking)
			sm.logger.Info("Hytale server files not found, downloading", "uuid", server.UUID)
			if err := sm.checkAndApplyHytaleUpdate(ctx, server, serverDir); err != nil {
				server.Status = "install_failed"
				sm.saveServer(server)
				sm.reportStatusToPanel(server.UUID, "install_failed", "Hytale server files not found. Download may have failed.")
				return fmt.Errorf("Hytale server files not found - download failed: %w", err)
			}
		} else if autoUpdateEnabled {
			// Server files exist and auto-update is enabled - check for updates before starting (blocking)
			sm.logger.Info("Checking for Hytale updates before starting", "uuid", server.UUID)
			if err := sm.checkAndApplyHytaleUpdate(ctx, server, serverDir); err != nil {
				// Non-fatal - log warning and continue with existing version
				sm.logger.Warn("Hytale update check failed, starting with current version", "uuid", server.UUID, "error", err)
			}
		} else {
			sm.logger.Info("Hytale auto-update disabled, starting with current version", "uuid", server.UUID)
		}
	}

	// Check if existing container needs to be recreated (startup_cmd changed)
	if server.ContainerID != "" {
		containerCmd, err := sm.docker.GetContainerCmd(ctx, server.ContainerID)
		if err != nil {
			// Container doesn't exist or error - clear the ID so it gets recreated
			sm.logger.Warn("failed to inspect container, will recreate", "uuid", server.UUID, "error", err)
			server.ContainerID = ""
		} else if !slicesEqual(containerCmd, server.StartupCmd) {
			// Startup command changed - need to recreate container
			sm.logger.Info("startup command changed, recreating container",
				"uuid", server.UUID,
				"old_cmd", containerCmd,
				"new_cmd", server.StartupCmd,
			)
			if err := sm.docker.RemoveContainer(ctx, server.ContainerID, true); err != nil {
				sm.logger.Warn("failed to remove old container", "uuid", server.UUID, "error", err)
			}
			server.ContainerID = ""
			sm.saveServer(server)
		}
	}

	// Create container if doesn't exist
	if server.ContainerID == "" {
		// Determine host ports for management protocols
		// Game port + 10000 = RCON host port (e.g., 25565 -> 35565)
		// Game port + 20000 = Management Protocol host port (e.g., 25565 -> 45565)
		rconHostPort := 25575         // default
		managementHostPort := 25576   // default
		for _, hostPort := range server.Ports {
			rconHostPort = hostPort + 10000
			managementHostPort = hostPort + 20000
			break // use first port
		}

		// For Hytale, container port = host port (uses --bind 0.0.0.0:PORT)
		// For Minecraft, container port is 25565 mapped to host port
		ports := server.Ports
		if server.GameType == games.GameHytale {
			ports = make(map[int]int)
			for _, hostPort := range server.Ports {
				ports[hostPort] = hostPort // container port = host port
			}
		}

		cfg := &docker.ServerConfig{
			UUID:               server.UUID,
			Name:               fmt.Sprintf("roots-%s", server.UUID[:8]),
			Image:              server.Image,
			Cmd:                server.StartupCmd,
			Env:                server.Env,
			MemoryLimit:        server.Memory,
			CPULimit:           server.CPU,
			ServerDir:          serverDir,
			Ports:              ports,
			WorkingDir:         "/server",
			RCONPort:           25575,              // RCON port inside container
			RCONHostPort:       rconHostPort,       // Mapped to localhost only
			ManagementPort:     25576,              // Management Protocol port inside container (1.21.9+)
			ManagementHostPort: managementHostPort, // Mapped to localhost only
		}

		// For Hytale, mount /etc/machine-id to provide a stable hardware UUID
		// This allows credential encryption to persist across container restarts
		if server.GameType == games.GameHytale {
			if _, err := os.Stat("/etc/machine-id"); err == nil {
				cfg.ExtraMounts = []mount.Mount{
					{
						Type:     mount.TypeBind,
						Source:   "/etc/machine-id",
						Target:   "/etc/machine-id",
						ReadOnly: true,
					},
				}
			}
		}

		containerID, err := sm.docker.CreateContainer(ctx, cfg)
		if err != nil {
			return fmt.Errorf("failed to create container: %w", err)
		}
		server.ContainerID = containerID
	}

	// Start container
	server.Status = "starting"
	if err := sm.docker.StartContainer(ctx, server.ContainerID); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	// Update container resources to match current server config
	// This ensures any resource changes made while stopped are applied
	if err := sm.docker.UpdateContainerResources(ctx, server.ContainerID, server.Memory, server.CPU); err != nil {
		sm.logger.Warn("failed to update container resources after start",
			"error", err,
			"uuid", server.UUID,
			"memory", server.Memory,
			"cpu", server.CPU,
		)
	}

	server.Status = "online"
	return nil
}

func (sm *ServerManager) stopServer(ctx context.Context, server *Server) error {
	if server.ContainerID == "" {
		return nil
	}

	server.Status = "stopping"
	if err := sm.docker.StopContainer(ctx, server.ContainerID, 30); err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	server.Status = "offline"

	// Close any active console connections
	sm.closeConsoleConns(server.UUID)

	// Close Management Protocol connection
	sm.closeManagementConnection(server.UUID)

	// Close RCON connection
	sm.closeRCONConnection(server.UUID)

	return nil
}

func (sm *ServerManager) killServer(ctx context.Context, server *Server) error {
	if server.ContainerID == "" {
		return nil
	}

	if err := sm.docker.KillContainer(ctx, server.ContainerID); err != nil {
		return fmt.Errorf("failed to kill container: %w", err)
	}

	server.Status = "offline"

	// Close any active console connections
	sm.closeConsoleConns(server.UUID)

	// Close Management Protocol connection
	sm.closeManagementConnection(server.UUID)

	// Close RCON connection
	sm.closeRCONConnection(server.UUID)

	return nil
}

// getUpgrader returns a WebSocket upgrader with origin validation
func (sm *ServerManager) getUpgrader() websocket.Upgrader {
	return websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     sm.checkOrigin,
	}
}

// checkOrigin validates WebSocket connection origins
// Allows: localhost origins for development, panel URL origin for production
func (sm *ServerManager) checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")

	// No origin header (e.g., CLI tools, curl) - allow if authenticated
	if origin == "" {
		return true
	}

	// Allow localhost origins for development
	if isLocalhostOrigin(origin) {
		return true
	}

	// Allow the configured panel URL origin
	panelURL := sm.config.Panel.URL
	if panelURL != "" && strings.HasPrefix(origin, panelURL) {
		return true
	}

	// Also allow if origin matches just the host part of panel URL
	if panelURL != "" {
		// Extract host from panel URL (handle http:// and https://)
		panelHost := strings.TrimPrefix(panelURL, "https://")
		panelHost = strings.TrimPrefix(panelHost, "http://")
		panelHost = strings.Split(panelHost, "/")[0] // Remove path

		originHost := strings.TrimPrefix(origin, "https://")
		originHost = strings.TrimPrefix(originHost, "http://")
		originHost = strings.Split(originHost, "/")[0]

		if originHost == panelHost {
			return true
		}
	}

	sm.logger.Warn("WebSocket connection rejected: origin not allowed",
		"origin", origin,
		"panel_url", panelURL,
	)
	return false
}

// isLocalhostOrigin checks if the origin is a localhost address
func isLocalhostOrigin(origin string) bool {
	localhostPrefixes := []string{
		"http://localhost",
		"https://localhost",
		"http://127.0.0.1",
		"https://127.0.0.1",
		"http://[::1]",
		"https://[::1]",
		"http://0.0.0.0",
		"https://0.0.0.0",
	}
	for _, prefix := range localhostPrefixes {
		if strings.HasPrefix(origin, prefix) {
			return true
		}
	}
	return false
}

// Console handles WebSocket connection for console streaming
func (sm *ServerManager) Console(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	sm.mu.RLock()
	server, ok := sm.servers[uuid]
	sm.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Allow connections during installation (for streaming install output)
	// or when server is running/starting
	validStatuses := map[string]bool{
		"installing": true,
		"online":     true,
		"starting":   true,
	}
	if !validStatuses[server.Status] {
		http.Error(w, "Server is not running or installing", http.StatusBadRequest)
		return
	}

	// Upgrade to WebSocket
	upgrader := sm.getUpgrader()
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		sm.logger.Error("websocket upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	// Track this console connection
	sm.registerConsoleConn(uuid, conn)
	defer sm.unregisterConsoleConn(uuid, conn)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// During installation, we just keep the connection open for broadcast messages
	// The installation process will push output via broadcastToConsole
	if server.Status == "installing" {
		conn.WriteMessage(websocket.TextMessage, []byte("[Sprout] Installation in progress, streaming output...\n"))
		// Keep connection alive until context is cancelled or connection closes
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Check if connection is still alive by reading (will block until message or close)
				_, _, err := conn.ReadMessage()
				if err != nil {
					return
				}
			}
		}
	}

	// For running servers, require a container
	if server.ContainerID == "" {
		conn.WriteMessage(websocket.TextMessage, []byte("[Sprout] Waiting for container...\n"))
		return
	}

	// Send historical logs first (last 5 lines)
	sm.sendHistoricalLogs(ctx, conn, server.ContainerID)

	// Attach to container for live streaming
	attach, err := sm.docker.AttachContainer(ctx, server.ContainerID)
	if err != nil {
		sm.logger.Error("failed to attach to container", "error", err)
		conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Error: %v", err)))
		return
	}
	defer attach.Close()

	// Read from container -> write to WebSocket
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := attach.Reader.Read(buf)
			if err != nil {
				cancel()
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, buf[:n]); err != nil {
				cancel()
				return
			}
		}
	}()

	// Read from WebSocket -> write to container
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			return
		}
		// Add newline for command execution
		message = append(message, '\n')
		attach.Conn.Write(message)
	}
}

// sendHistoricalLogs sends the last N lines of container logs to the WebSocket
func (sm *ServerManager) sendHistoricalLogs(ctx context.Context, conn *websocket.Conn, containerID string) {
	logs, err := sm.docker.GetContainerLogs(ctx, containerID, "5", false)
	if err != nil {
		sm.logger.Error("failed to get historical logs", "error", err)
		return
	}
	defer logs.Close()

	buf := make([]byte, 8192)
	for {
		n, err := logs.Read(buf)
		if n > 0 {
			// Docker multiplexed stream has 8-byte header per frame
			// Strip the header for cleaner output
			data := stripDockerHeader(buf[:n])
			if len(data) > 0 {
				conn.WriteMessage(websocket.TextMessage, data)
			}
		}
		if err != nil {
			break
		}
	}
}

// stripDockerHeader removes Docker multiplexed stream headers from log output
// Docker log format: [8-byte header][payload] where header is [stream_type, 0, 0, 0, size(4 bytes)]
func stripDockerHeader(data []byte) []byte {
	var result []byte
	for len(data) >= 8 {
		// Read the size from header bytes 4-7 (big endian)
		size := int(data[4])<<24 | int(data[5])<<16 | int(data[6])<<8 | int(data[7])
		if size <= 0 || 8+size > len(data) {
			// Invalid size or not enough data, return remaining as-is
			result = append(result, data...)
			break
		}
		// Append the payload (skip 8-byte header)
		result = append(result, data[8:8+size]...)
		data = data[8+size:]
	}
	// Append any remaining data that doesn't fit the pattern
	if len(data) > 0 && len(data) < 8 {
		result = append(result, data...)
	}
	return result
}

// StatsResponse combines container stats with disk usage
type StatsResponse struct {
	CPUPercent    float64 `json:"CPUPercent"`
	MemoryUsage   uint64  `json:"MemoryUsage"`
	MemoryLimit   uint64  `json:"MemoryLimit"`
	MemoryPercent float64 `json:"MemoryPercent"`
	NetworkRx     uint64  `json:"NetworkRx"`
	NetworkTx     uint64  `json:"NetworkTx"`
	DiskUsage     uint64  `json:"DiskUsage"`
	DiskLimit     uint64  `json:"DiskLimit"`
}

// Stats handles WebSocket connection for stats streaming
func (sm *ServerManager) Stats(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	sm.mu.RLock()
	server, ok := sm.servers[uuid]
	sm.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	if server.ContainerID == "" {
		http.Error(w, "Server has no container", http.StatusBadRequest)
		return
	}

	// Get server directory for disk usage calculation
	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	// Upgrade to WebSocket
	upgrader := sm.getUpgrader()
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		sm.logger.Error("websocket upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var diskUsage uint64
	tickCount := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tickCount++

			stats, err := sm.docker.GetContainerStats(ctx, server.ContainerID)
			if err != nil {
				continue
			}

			// Calculate disk usage every 5 seconds to reduce I/O
			if tickCount%5 == 1 {
				diskUsage = getDirSize(serverDir)
			}

			response := StatsResponse{
				CPUPercent:    stats.CPUPercent,
				MemoryUsage:   stats.MemoryUsage,
				MemoryLimit:   stats.MemoryLimit,
				MemoryPercent: stats.MemoryPercent,
				NetworkRx:     stats.NetworkRx,
				NetworkTx:     stats.NetworkTx,
				DiskUsage:     diskUsage,
				DiskLimit:     uint64(server.DiskLimit),
			}

			data, _ := json.Marshal(response)
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				return
			}
		}
	}
}

// getDirSize calculates the total size of a directory recursively
func getDirSize(path string) uint64 {
	var size uint64
	filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err == nil {
				size += uint64(info.Size())
			}
		}
		return nil
	})
	return size
}

// PlayersResponse contains player information for WebSocket streaming
type PlayersResponse struct {
	Online  int                    `json:"online"`
	Max     int                    `json:"max"`
	Players []minecraft.PlayerInfo `json:"players"`
	MOTD    string                 `json:"motd,omitempty"`
	Version string                 `json:"version,omitempty"`
	Error   string                 `json:"error,omitempty"`
}

// Players handles WebSocket connection for player list streaming
func (sm *ServerManager) Players(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	sm.mu.RLock()
	server, ok := sm.servers[uuid]
	sm.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Get the Minecraft port (usually 25565 inside container)
	hostPort := 0
	for containerPort, hp := range server.Ports {
		if containerPort == 25565 {
			hostPort = hp
			break
		}
	}

	if hostPort == 0 {
		http.Error(w, "Server has no Minecraft port mapped", http.StatusBadRequest)
		return
	}

	// Upgrade to WebSocket
	upgrader := sm.getUpgrader()
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		sm.logger.Error("websocket upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Poll every 5 seconds
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Send initial status immediately
	sm.sendPlayerStatus(conn, uuid, hostPort)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check if server is still online
			sm.mu.RLock()
			currentServer, exists := sm.servers[uuid]
			sm.mu.RUnlock()

			if !exists || (currentServer.Status != "online" && currentServer.Status != "starting") {
				// Server went offline, send empty response
				response := PlayersResponse{
					Online:  0,
					Max:     0,
					Players: []minecraft.PlayerInfo{},
					Error:   "server offline",
				}
				data, _ := json.Marshal(response)
				if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
					return
				}
				continue
			}

			sm.sendPlayerStatus(conn, uuid, hostPort)
		}
	}
}

// sendPlayerStatus gets player info and sends it to the WebSocket
// Tries Management Protocol (1.21.9+) first for full player list with UUIDs,
// then falls back to SLP (Server List Ping) for older versions
// Does NOT use RCON for polling as that spams the server console
func (sm *ServerManager) sendPlayerStatus(conn *websocket.Conn, uuid string, hostPort int) {
	var response PlayersResponse

	// Check if server is online before trying to connect
	sm.mu.RLock()
	server, exists := sm.servers[uuid]
	sm.mu.RUnlock()

	if !exists || server.Status != "online" {
		// Server is offline - return empty response without trying to connect
		response = PlayersResponse{
			Online:  0,
			Max:     0,
			Players: []minecraft.PlayerInfo{},
		}
		data, _ := json.Marshal(response)
		conn.WriteMessage(websocket.TextMessage, data)
		return
	}

	// Try Management Protocol first (1.21.9+) - provides full player list with UUIDs
	// Uses persistent connection to avoid connection spam in Minecraft console
	if mgmtClient, err := sm.getPersistentManagementClient(uuid); err == nil {
		if players, err := mgmtClient.QueryPlayers(); err == nil {
			// Successfully using Management Protocol (no logging to reduce noise)
			// Get max players from SLP (Management Protocol doesn't provide it directly)
			maxPlayers := 20
			if status, err := minecraft.PingServer("localhost", hostPort); err == nil {
				maxPlayers = status.Max
			}

			response = PlayersResponse{
				Online:  len(players),
				Max:     maxPlayers,
				Players: players,
			}
			data, _ := json.Marshal(response)
			conn.WriteMessage(websocket.TextMessage, data)
			return
		} else {
			// Query failed - connection may be stale, close it so it reconnects next time
			sm.closeManagementConnection(uuid)
			sm.logger.Debug("Management Protocol query failed, falling back to SLP", "uuid", uuid, "error", err)
		}
	} else {
		sm.logger.Debug("Management Protocol not available, using SLP", "uuid", uuid, "error", err)
	}

	// Fall back to SLP (Server List Ping) - works on all versions, no console spam
	status, err := minecraft.PingServer("localhost", hostPort)

	if err != nil {
		response = PlayersResponse{
			Online:  0,
			Max:     0,
			Players: []minecraft.PlayerInfo{},
			Error:   err.Error(),
		}
	} else {
		response = PlayersResponse{
			Online:  status.Online,
			Max:     status.Max,
			Players: status.Players,
			MOTD:    status.MOTD,
			Version: status.Version,
		}
	}

	data, _ := json.Marshal(response)
	conn.WriteMessage(websocket.TextMessage, data)
}

// getVersionFromEnv extracts Minecraft version from environment variables
// Checks common version variable names used by different eggs/seeds
func getVersionFromEnv(env map[string]string) string {
	versionKeys := []string{
		"MINECRAFT_VERSION",
		"MC_VERSION",
		"VANILLA_VERSION",
		"VERSION",
	}
	for _, key := range versionKeys {
		if v, ok := env[key]; ok && v != "" {
			return v
		}
	}
	return ""
}

// chownRecursive changes ownership of a directory and all its contents
func chownRecursive(path string, uid, gid int) error {
	return filepath.WalkDir(path, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(name, uid, gid)
	})
}

// parseCommand splits a command string into args, handling quotes
func parseCommand(cmd string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := rune(0)

	for _, r := range cmd {
		switch {
		case r == '"' || r == '\'':
			if inQuote && r == quoteChar {
				inQuote = false
			} else if !inQuote {
				inQuote = true
				quoteChar = r
			} else {
				current.WriteRune(r)
			}
		case r == ' ' && !inQuote:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

// portsEqual compares two port mappings for equality
func portsEqual(a, b map[int]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if b[i] != v {
			return false
		}
	}
	return true
}

// ============================================================================
// ServerProvider interface implementation for Minecraft handlers
// ============================================================================

// GetServer returns server info by UUID (implements mchandlers.ServerProvider)
func (sm *ServerManager) GetServer(uuid string) (mchandlers.ServerInfo, bool) {
	sm.mu.RLock()
	server, ok := sm.servers[uuid]
	sm.mu.RUnlock()

	if !ok {
		return mchandlers.ServerInfo{}, false
	}

	return mchandlers.ServerInfo{
		UUID:     server.UUID,
		Name:     server.Name,
		GameType: server.GameType,
		Status:   server.Status,
	}, true
}

// GetRCONClient returns a persistent RCON client (implements mchandlers.ServerProvider)
func (sm *ServerManager) GetRCONClient(uuid string) (*minecraft.RCONClient, error) {
	return sm.getPersistentRCONClient(uuid)
}

// GetManagementClient returns a persistent Management Protocol client (implements mchandlers.ServerProvider)
func (sm *ServerManager) GetManagementClient(uuid string) (*minecraft.ManagementClient, error) {
	return sm.getPersistentManagementClient(uuid)
}

// CloseRCONConnection closes the RCON connection (implements mchandlers.ServerProvider)
func (sm *ServerManager) CloseRCONConnection(uuid string) {
	sm.closeRCONConnection(uuid)
}

// GetServerDir returns the directory path for a server (implements mchandlers.ServerProvider)
func (sm *ServerManager) GetServerDir(uuid string) string {
	return filepath.Join(sm.config.Storage.Servers, uuid)
}

// ResolvePath resolves and validates a relative path (implements mchandlers.ServerProvider)
func (sm *ServerManager) ResolvePath(serverDir, relativePath string) (string, error) {
	return sm.resolvePath(serverDir, relativePath)
}

// GetMinecraftHandlers returns the Minecraft handlers instance
func (sm *ServerManager) GetMinecraftHandlers() *mchandlers.MinecraftHandlers {
	return mchandlers.NewMinecraftHandlers(sm, sm.logger)
}

// ============================================================================
// HytaleHandlers ServerProvider interface implementation
// ============================================================================

// hytaleServerProvider adapts ServerManager for Hytale handlers
type hytaleServerProvider struct {
	sm *ServerManager
}

// GetServer returns server info by UUID (implements hthandlers.ServerProvider)
func (p *hytaleServerProvider) GetServer(uuid string) (hthandlers.ServerInfo, bool) {
	p.sm.mu.RLock()
	server, ok := p.sm.servers[uuid]
	p.sm.mu.RUnlock()

	if !ok {
		return hthandlers.ServerInfo{}, false
	}

	return hthandlers.ServerInfo{
		UUID:     server.UUID,
		Name:     server.Name,
		GameType: server.GameType,
		Status:   server.Status,
	}, true
}

// GetServerDir returns the directory path for a server
func (p *hytaleServerProvider) GetServerDir(uuid string) string {
	return filepath.Join(p.sm.config.Storage.Servers, uuid)
}

// ResolvePath resolves and validates a relative path
func (p *hytaleServerProvider) ResolvePath(serverDir, relativePath string) (string, error) {
	return p.sm.resolvePath(serverDir, relativePath)
}

// GetHytaleHandlers returns the Hytale handlers instance
func (sm *ServerManager) GetHytaleHandlers() *hthandlers.HytaleHandlers {
	provider := &hytaleServerProvider{sm: sm}
	return hthandlers.NewHytaleHandlers(provider, sm.logger)
}

// ============================================================================
// Hytale-specific handlers
// ============================================================================

// HytaleVersionResponse contains Hytale version information
type HytaleVersionResponse struct {
	InstalledVersion string `json:"installed_version"`
	Patchline        string `json:"patchline"`
	AutoUpdate       bool   `json:"auto_update"`
}

// GetHytaleVersion returns the installed Hytale version
func (sm *ServerManager) GetHytaleVersion(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	sm.mu.RLock()
	server, ok := sm.servers[uuid]
	sm.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	if server.GameType != games.GameHytale {
		http.Error(w, "Not a Hytale server", http.StatusBadRequest)
		return
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	// Create downloader client to read version
	dockerClient, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		http.Error(w, "Failed to create Docker client", http.StatusInternalServerError)
		return
	}
	defer dockerClient.Close()

	downloader := hytale.NewDownloaderClient(dockerClient, sm.logger)
	version, _ := downloader.GetInstalledVersion(serverDir)

	patchline := server.Env["HYTALE_PATCHLINE"]
	if patchline == "" {
		patchline = "release"
	}

	autoUpdate := server.Env["HYTALE_AUTO_UPDATE"]
	autoUpdateEnabled := autoUpdate == "" || autoUpdate == "true" || autoUpdate == "1"

	response := HytaleVersionResponse{
		InstalledVersion: version,
		Patchline:        patchline,
		AutoUpdate:       autoUpdateEnabled,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HytaleUpdateCheckResponse contains update check results
type HytaleUpdateCheckResponse struct {
	UpdateAvailable bool   `json:"update_available"`
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version,omitempty"`
	Error           string `json:"error,omitempty"`
}

// CheckHytaleUpdate checks if a Hytale update is available
func (sm *ServerManager) CheckHytaleUpdate(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	sm.mu.RLock()
	server, ok := sm.servers[uuid]
	sm.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	if server.GameType != games.GameHytale {
		http.Error(w, "Not a Hytale server", http.StatusBadRequest)
		return
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	dockerClient, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		http.Error(w, "Failed to create Docker client", http.StatusInternalServerError)
		return
	}
	defer dockerClient.Close()

	downloader := hytale.NewDownloaderClient(dockerClient, sm.logger)

	// Get current version
	currentVersion, _ := downloader.GetInstalledVersion(serverDir)

	// Check for update
	hasUpdate, latestVersion, err := downloader.CheckUpdate(r.Context(), serverDir, nil)

	response := HytaleUpdateCheckResponse{
		UpdateAvailable: hasUpdate,
		CurrentVersion:  currentVersion,
		LatestVersion:   latestVersion,
	}

	if err != nil {
		response.Error = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HytaleUpdateApplyResponse contains update apply results
type HytaleUpdateApplyResponse struct {
	Success    bool   `json:"success"`
	NewVersion string `json:"new_version,omitempty"`
	Error      string `json:"error,omitempty"`
}

// ApplyHytaleUpdate applies a Hytale update
func (sm *ServerManager) ApplyHytaleUpdate(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	sm.mu.RLock()
	server, ok := sm.servers[uuid]
	sm.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	if server.GameType != games.GameHytale {
		http.Error(w, "Not a Hytale server", http.StatusBadRequest)
		return
	}

	// Server must be offline to update
	if server.Status == "online" || server.Status == "starting" {
		http.Error(w, "Server must be stopped to apply update", http.StatusBadRequest)
		return
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	dockerClient, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		response := HytaleUpdateApplyResponse{
			Success: false,
			Error:   "Failed to create Docker client",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}
	defer dockerClient.Close()

	downloader := hytale.NewDownloaderClient(dockerClient, sm.logger)

	patchline := server.Env["HYTALE_PATCHLINE"]
	if patchline == "" {
		patchline = "release"
	}

	// Callback for output
	callback := func(line string, event *gameshytale.ConsoleEvent) {
		sm.logger.Debug("Hytale update output", "uuid", uuid, "line", line)
		sm.broadcastToConsole(uuid, line)

		if event != nil && event.Type == gameshytale.EventAuthPrompt {
			sm.broadcastHytaleAuthEvent(uuid, event.URL, event.Code, "downloader")
		}
	}

	result, err := downloader.DownloadServer(r.Context(), serverDir, patchline, callback)

	response := HytaleUpdateApplyResponse{
		Success: result != nil && result.Success,
	}

	if err != nil {
		response.Error = err.Error()
	} else if result != nil {
		if result.Success {
			response.NewVersion = result.Version
			// Update server version
			if result.Version != "" {
				server.Version = result.Version
				downloader.SaveInstalledVersion(serverDir, result.Version)
				sm.saveServer(server)
			}
		} else {
			response.Error = result.Error
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
