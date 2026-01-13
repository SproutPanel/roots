package handlers

import (
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/sproutpanel/roots/internal/config"
	"github.com/sproutpanel/roots/internal/docker"
)

// NodeManager handles node-level stats
type NodeManager struct {
	config    *config.Config
	docker    *docker.Client
	serverMgr *ServerManager
	logger    *slog.Logger
}

// NewNodeManager creates a new node manager
func NewNodeManager(cfg *config.Config, dockerClient *docker.Client, logger *slog.Logger) *NodeManager {
	return &NodeManager{
		config: cfg,
		docker: dockerClient,
		logger: logger,
	}
}

// SetServerManager sets the server manager reference (called after both are created)
func (nm *NodeManager) SetServerManager(sm *ServerManager) {
	nm.serverMgr = sm
}

// UpdateConfig updates the manager's configuration
func (nm *NodeManager) UpdateConfig(cfg *config.Config) {
	nm.config = cfg
}

// getUpgrader returns a WebSocket upgrader with origin validation
func (nm *NodeManager) getUpgrader() websocket.Upgrader {
	return websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     nm.checkOrigin,
	}
}

// checkOrigin validates WebSocket connection origins
func (nm *NodeManager) checkOrigin(r *http.Request) bool {
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
	panelURL := nm.config.Panel.URL
	if panelURL != "" && strings.HasPrefix(origin, panelURL) {
		return true
	}

	// Also allow if origin matches just the host part of panel URL
	if panelURL != "" {
		panelHost := strings.TrimPrefix(panelURL, "https://")
		panelHost = strings.TrimPrefix(panelHost, "http://")
		panelHost = strings.Split(panelHost, "/")[0]

		originHost := strings.TrimPrefix(origin, "https://")
		originHost = strings.TrimPrefix(originHost, "http://")
		originHost = strings.Split(originHost, "/")[0]

		if originHost == panelHost {
			return true
		}
	}

	nm.logger.Warn("WebSocket connection rejected: origin not allowed",
		"origin", origin,
		"panel_url", panelURL,
	)
	return false
}

// NodeStatsResponse contains node-level resource stats
type NodeStatsResponse struct {
	CPUPercent    float64 `json:"CPUPercent"`
	CPUCores      int     `json:"CPUCores"`
	MemoryUsed    uint64  `json:"MemoryUsed"`
	MemoryTotal   uint64  `json:"MemoryTotal"`
	MemoryPercent float64 `json:"MemoryPercent"`
	DiskUsed      uint64  `json:"DiskUsed"`
	DiskTotal     uint64  `json:"DiskTotal"`
	DiskPercent   float64 `json:"DiskPercent"`
	NetworkRx     uint64  `json:"NetworkRx"`
	NetworkTx     uint64  `json:"NetworkTx"`
}

// Stats handles WebSocket connection for node stats streaming
func (nm *NodeManager) Stats(w http.ResponseWriter, r *http.Request) {
	// Get storage path for disk stats
	storagePath := nm.config.Storage.Servers

	// Upgrade to WebSocket
	upgrader := nm.getUpgrader()
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		nm.logger.Error("websocket upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	// Use a background context for the WebSocket loop - don't inherit request timeout
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle WebSocket close from client
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				cancel()
				return
			}
		}
	}()

	// Send stats every 2 seconds
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var diskUsed uint64
	tickCount := 0

	// Get CPU core count (doesn't change, so get once)
	cpuCores, _ := cpu.Counts(true) // logical cores

	// Get initial disk stats
	diskUsed = nm.calculateDirectorySize(storagePath)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tickCount++

			// Get CPU percent (non-blocking, returns last calculated value)
			cpuPercents, err := cpu.Percent(0, false)
			cpuPercent := 0.0
			if err == nil && len(cpuPercents) > 0 {
				cpuPercent = cpuPercents[0]
			}

			// Aggregate memory and network usage from all managed containers
			var memUsed uint64
			var netRx, netTx uint64
			var memTotal uint64 = nm.config.Resources.MemoryBytes
			if nm.serverMgr != nil {
				memUsed, netRx, netTx = nm.aggregateContainerStats(ctx)
			}
			var memPercent float64
			if memTotal > 0 {
				memPercent = float64(memUsed) / float64(memTotal) * 100.0
			}

			// Update disk stats every 10 ticks (20 seconds) to reduce I/O
			if tickCount%10 == 1 {
				diskUsed = nm.calculateDirectorySize(storagePath)
			}

			var diskTotal uint64 = nm.config.Resources.DiskBytes
			var diskPercent float64
			if diskTotal > 0 {
				diskPercent = float64(diskUsed) / float64(diskTotal) * 100.0
			}

			response := NodeStatsResponse{
				CPUPercent:    cpuPercent,
				CPUCores:      cpuCores,
				MemoryUsed:    memUsed,
				MemoryTotal:   memTotal,
				MemoryPercent: memPercent,
				DiskUsed:      diskUsed,
				DiskTotal:     diskTotal,
				DiskPercent:   diskPercent,
				NetworkRx:     netRx,
				NetworkTx:     netTx,
			}

			data, _ := json.Marshal(response)
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				return
			}
		}
	}
}

// aggregateContainerStats sums memory and network usage from all managed containers
func (nm *NodeManager) aggregateContainerStats(ctx context.Context) (uint64, uint64, uint64) {
	var totalMemory uint64
	var totalNetRx uint64
	var totalNetTx uint64

	// Use a short timeout for Docker operations to prevent blocking
	dockerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// List all managed containers
	containers, err := nm.docker.ListManagedContainers(dockerCtx)
	if err != nil {
		// Don't log on every failure - just return zeros
		return 0, 0, 0
	}

	for _, container := range containers {
		if container.State != "running" {
			continue
		}
		stats, err := nm.docker.GetContainerStats(dockerCtx, container.ID)
		if err != nil {
			continue
		}
		totalMemory += stats.MemoryUsage
		totalNetRx += stats.NetworkRx
		totalNetTx += stats.NetworkTx
	}

	return totalMemory, totalNetRx, totalNetTx
}

// GetStats returns current node stats via HTTP (single request, not WebSocket)
func (nm *NodeManager) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	storagePath := nm.config.Storage.Servers

	// Get CPU percent
	cpuPercents, err := cpu.Percent(0, false)
	cpuPercent := 0.0
	if err == nil && len(cpuPercents) > 0 {
		cpuPercent = cpuPercents[0]
	}

	// Get CPU core count
	cpuCores, _ := cpu.Counts(true)

	// Aggregate memory and network usage from all managed containers
	var memUsed uint64
	var netRx, netTx uint64
	var memTotal uint64 = nm.config.Resources.MemoryBytes
	if nm.serverMgr != nil {
		memUsed, netRx, netTx = nm.aggregateContainerStats(ctx)
	}
	var memPercent float64
	if memTotal > 0 {
		memPercent = float64(memUsed) / float64(memTotal) * 100.0
	}

	// Calculate disk usage
	diskUsed := nm.calculateDirectorySize(storagePath)
	var diskTotal uint64 = nm.config.Resources.DiskBytes
	var diskPercent float64
	if diskTotal > 0 {
		diskPercent = float64(diskUsed) / float64(diskTotal) * 100.0
	}

	response := NodeStatsResponse{
		CPUPercent:    cpuPercent,
		CPUCores:      cpuCores,
		MemoryUsed:    memUsed,
		MemoryTotal:   memTotal,
		MemoryPercent: memPercent,
		DiskUsed:      diskUsed,
		DiskTotal:     diskTotal,
		DiskPercent:   diskPercent,
		NetworkRx:     netRx,
		NetworkTx:     netTx,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// calculateDirectorySize calculates the total size of all files in a directory
func (nm *NodeManager) calculateDirectorySize(path string) uint64 {
	var totalSize uint64

	// Check if directory exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return 0
	}

	err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err == nil {
				totalSize += uint64(info.Size())
			}
		}
		return nil
	})

	if err != nil {
		nm.logger.Error("failed to calculate directory size", "error", err, "path", path)
	}

	return totalSize
}

// SystemIPsResponse contains the list of system IP addresses
type SystemIPsResponse struct {
	IPAddresses []string `json:"ip_addresses"`
}

// GetSystemIPs handles GET /api/node/ips - returns all non-loopback IPv4 addresses
func (nm *NodeManager) GetSystemIPs(w http.ResponseWriter, r *http.Request) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		nm.logger.Error("failed to get interface addresses", "error", err)
		http.Error(w, "Failed to get IP addresses", http.StatusInternalServerError)
		return
	}

	var ips []string
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		// Skip non-IPv4 addresses
		if ipNet.IP.To4() == nil {
			continue
		}

		// Skip loopback addresses
		if ipNet.IP.IsLoopback() {
			continue
		}

		ips = append(ips, ipNet.IP.String())
	}

	response := SystemIPsResponse{
		IPAddresses: ips,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// ImagePruneResponse contains the result of pruning Docker images
type ImagePruneResponse struct {
	ImagesDeleted  []string `json:"images_deleted"`
	SpaceReclaimed uint64   `json:"space_reclaimed"`
}

// PruneDockerImages handles DELETE /api/node/docker/images/prune - removes unused Docker images
func (nm *NodeManager) PruneDockerImages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	report, err := nm.docker.PruneImages(ctx)
	if err != nil {
		nm.logger.Error("failed to prune Docker images", "error", err)
		http.Error(w, "Failed to prune images", http.StatusInternalServerError)
		return
	}

	response := ImagePruneResponse{
		ImagesDeleted:  report.ImagesDeleted,
		SpaceReclaimed: report.SpaceReclaimed,
	}

	nm.logger.Info("pruned Docker images",
		"images_deleted", len(report.ImagesDeleted),
		"space_reclaimed", report.SpaceReclaimed,
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
