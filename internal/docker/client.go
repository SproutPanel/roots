package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

// Client wraps the Docker client with game server specific operations
type Client struct {
	docker      *client.Client
	networkName string
}

// NewClient creates a new Docker client
func NewClient(socketPath string, networkName string) (*Client, error) {
	opts := []client.Opt{
		client.WithHost("unix://" + socketPath),
		client.WithAPIVersionNegotiation(),
	}

	docker, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	c := &Client{
		docker:      docker,
		networkName: networkName,
	}

	// Ensure network exists
	if err := c.ensureNetwork(context.Background()); err != nil {
		return nil, err
	}

	return c, nil
}

// Close closes the Docker client
func (c *Client) Close() error {
	return c.docker.Close()
}

// Ping checks if Docker is accessible
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.docker.Ping(ctx)
	return err
}

// ensureNetwork creates the roots network if it doesn't exist
func (c *Client) ensureNetwork(ctx context.Context) error {
	networks, err := c.docker.NetworkList(ctx, types.NetworkListOptions{
		Filters: filters.NewArgs(filters.Arg("name", c.networkName)),
	})
	if err != nil {
		return fmt.Errorf("failed to list networks: %w", err)
	}

	if len(networks) == 0 {
		_, err = c.docker.NetworkCreate(ctx, c.networkName, types.NetworkCreate{
			Driver: "bridge",
		})
		if err != nil {
			return fmt.Errorf("failed to create network: %w", err)
		}
	}

	return nil
}

// ServerConfig holds configuration for creating a game server container
type ServerConfig struct {
	UUID           string
	Name           string
	Image          string
	Cmd            []string
	Env            map[string]string
	MemoryLimit    int64 // in bytes
	CPULimit       int64 // in millicores (1000 = 1 CPU)
	ServerDir      string
	MountTarget    string          // container path for server dir (default: /server)
	Ports          map[int]int // container port -> host port
	WorkingDir     string
	User           string
	StopSignal     string
	StopTimeout        int
	RCONPort           int // RCON port inside container (default 25575)
	RCONHostPort       int // RCON port on host (for localhost binding)
	ManagementPort     int // Management Protocol port inside container (1.21.9+)
	ManagementHostPort int // Management Protocol port on host (for localhost binding)
}

// CreateContainer creates a new container for a game server
func (c *Client) CreateContainer(ctx context.Context, cfg *ServerConfig) (string, error) {
	// Convert env map to slice
	env := make([]string, 0, len(cfg.Env))
	for k, v := range cfg.Env {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	// Build port bindings
	exposedPorts := nat.PortSet{}
	portBindings := nat.PortMap{}
	for containerPort, hostPort := range cfg.Ports {
		port := nat.Port(fmt.Sprintf("%d/tcp", containerPort))
		exposedPorts[port] = struct{}{}
		portBindings[port] = []nat.PortBinding{
			{HostIP: "0.0.0.0", HostPort: fmt.Sprintf("%d", hostPort)},
		}
		// Also bind UDP for game servers
		udpPort := nat.Port(fmt.Sprintf("%d/udp", containerPort))
		exposedPorts[udpPort] = struct{}{}
		portBindings[udpPort] = []nat.PortBinding{
			{HostIP: "0.0.0.0", HostPort: fmt.Sprintf("%d", hostPort)},
		}
	}

	// Add RCON port binding (localhost only for security)
	// This allows the daemon to connect to RCON on macOS/Windows where
	// container IPs aren't directly accessible from the host
	if cfg.RCONPort > 0 {
		rconPort := nat.Port(fmt.Sprintf("%d/tcp", cfg.RCONPort))
		exposedPorts[rconPort] = struct{}{}
		portBindings[rconPort] = []nat.PortBinding{
			{HostIP: "127.0.0.1", HostPort: fmt.Sprintf("%d", cfg.RCONHostPort)},
		}
	}

	// Add Management Protocol port binding (localhost only, 1.21.9+)
	// WebSocket-based JSON-RPC 2.0 protocol for server management
	if cfg.ManagementPort > 0 {
		mgmtPort := nat.Port(fmt.Sprintf("%d/tcp", cfg.ManagementPort))
		exposedPorts[mgmtPort] = struct{}{}
		portBindings[mgmtPort] = []nat.PortBinding{
			{HostIP: "127.0.0.1", HostPort: fmt.Sprintf("%d", cfg.ManagementHostPort)},
		}
	}

	// Container config
	containerConfig := &container.Config{
		Image:        cfg.Image,
		Cmd:          cfg.Cmd,
		Env:          env,
		ExposedPorts: exposedPorts,
		WorkingDir:   cfg.WorkingDir,
		User:         cfg.User,
		Tty:          true,
		OpenStdin:    true,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Labels: map[string]string{
			"roots.server.uuid": cfg.UUID,
			"roots.server.name": cfg.Name,
			"roots.managed":     "true",
		},
	}

	if cfg.StopSignal != "" {
		containerConfig.StopSignal = cfg.StopSignal
	}

	// Determine mount target (default to /server)
	mountTarget := cfg.MountTarget
	if mountTarget == "" {
		mountTarget = "/server"
	}

	// Host config
	hostConfig := &container.HostConfig{
		PortBindings: portBindings,
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: cfg.ServerDir,
				Target: mountTarget,
			},
		},
		Resources: container.Resources{
			Memory:   cfg.MemoryLimit,
			NanoCPUs: cfg.CPULimit * 1000000, // Convert millicores to nanocores
		},
		RestartPolicy: container.RestartPolicy{
			Name: "no",
		},
		NetworkMode: container.NetworkMode(c.networkName),
	}

	// Create container
	resp, err := c.docker.ContainerCreate(ctx, containerConfig, hostConfig, &network.NetworkingConfig{}, nil, cfg.Name)
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}

	return resp.ID, nil
}

// StartContainer starts a container
func (c *Client) StartContainer(ctx context.Context, containerID string) error {
	return c.docker.ContainerStart(ctx, containerID, types.ContainerStartOptions{})
}

// StopContainer stops a container gracefully
func (c *Client) StopContainer(ctx context.Context, containerID string, timeout int) error {
	timeoutDuration := time.Duration(timeout) * time.Second
	options := container.StopOptions{
		Timeout: &timeout,
	}
	_ = timeoutDuration // unused but kept for clarity
	return c.docker.ContainerStop(ctx, containerID, options)
}

// KillContainer forcefully kills a container
func (c *Client) KillContainer(ctx context.Context, containerID string) error {
	return c.docker.ContainerKill(ctx, containerID, "SIGKILL")
}

// RemoveContainer removes a container
func (c *Client) RemoveContainer(ctx context.Context, containerID string, force bool) error {
	return c.docker.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{
		Force:         force,
		RemoveVolumes: true,
	})
}

// UpdateContainerResources updates the memory and CPU limits for a running container
func (c *Client) UpdateContainerResources(ctx context.Context, containerID string, memoryLimit int64, cpuLimit int64) error {
	resources := container.UpdateConfig{
		Resources: container.Resources{
			Memory:   memoryLimit,
			NanoCPUs: cpuLimit * 1000000, // Convert millicores to nanocores
		},
	}

	_, err := c.docker.ContainerUpdate(ctx, containerID, resources)
	return err
}

// ContainerStatus represents the status of a container
type ContainerStatus struct {
	ID         string
	Status     string // created, running, paused, restarting, removing, exited, dead
	Running    bool
	StartedAt  time.Time
	FinishedAt time.Time
	ExitCode   int
}

// GetContainerStatus gets the status of a container
func (c *Client) GetContainerStatus(ctx context.Context, containerID string) (*ContainerStatus, error) {
	info, err := c.docker.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, err
	}

	startedAt, _ := time.Parse(time.RFC3339Nano, info.State.StartedAt)
	finishedAt, _ := time.Parse(time.RFC3339Nano, info.State.FinishedAt)

	return &ContainerStatus{
		ID:         info.ID,
		Status:     info.State.Status,
		Running:    info.State.Running,
		StartedAt:  startedAt,
		FinishedAt: finishedAt,
		ExitCode:   info.State.ExitCode,
	}, nil
}

// GetContainerIP returns the IP address of a container on the roots network
func (c *Client) GetContainerIP(ctx context.Context, containerID string) (string, error) {
	info, err := c.docker.ContainerInspect(ctx, containerID)
	if err != nil {
		return "", err
	}

	// Check for IP on our network first
	if netInfo, ok := info.NetworkSettings.Networks[c.networkName]; ok {
		if netInfo.IPAddress != "" {
			return netInfo.IPAddress, nil
		}
	}

	// Fall back to default bridge network
	if info.NetworkSettings.IPAddress != "" {
		return info.NetworkSettings.IPAddress, nil
	}

	return "", fmt.Errorf("no IP address found for container %s", containerID)
}

// ContainerStats represents resource usage stats
type ContainerStats struct {
	CPUPercent    float64
	MemoryUsage   uint64
	MemoryLimit   uint64
	MemoryPercent float64
	NetworkRx     uint64
	NetworkTx     uint64
}

// GetContainerStats gets resource usage stats for a container
func (c *Client) GetContainerStats(ctx context.Context, containerID string) (*ContainerStats, error) {
	stats, err := c.docker.ContainerStats(ctx, containerID, false)
	if err != nil {
		return nil, err
	}
	defer stats.Body.Close()

	var v types.StatsJSON
	if err := decodeStats(stats.Body, &v); err != nil {
		return nil, err
	}

	// Calculate CPU percent
	cpuPercent := calculateCPUPercent(&v)

	// Calculate memory percent
	memPercent := 0.0
	if v.MemoryStats.Limit > 0 {
		memPercent = float64(v.MemoryStats.Usage) / float64(v.MemoryStats.Limit) * 100.0
	}

	// Sum network stats
	var netRx, netTx uint64
	for _, netStats := range v.Networks {
		netRx += netStats.RxBytes
		netTx += netStats.TxBytes
	}

	return &ContainerStats{
		CPUPercent:    cpuPercent,
		MemoryUsage:   v.MemoryStats.Usage,
		MemoryLimit:   v.MemoryStats.Limit,
		MemoryPercent: memPercent,
		NetworkRx:     netRx,
		NetworkTx:     netTx,
	}, nil
}

// GetContainerLogs returns a reader for container logs
func (c *Client) GetContainerLogs(ctx context.Context, containerID string, tail string, follow bool) (io.ReadCloser, error) {
	return c.docker.ContainerLogs(ctx, containerID, types.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     follow,
		Tail:       tail,
		Timestamps: true,
	})
}

// AttachContainer attaches to a container's stdin/stdout/stderr
func (c *Client) AttachContainer(ctx context.Context, containerID string) (types.HijackedResponse, error) {
	return c.docker.ContainerAttach(ctx, containerID, types.ContainerAttachOptions{
		Stream: true,
		Stdin:  true,
		Stdout: true,
		Stderr: true,
	})
}

// PullImage pulls an image from a registry
func (c *Client) PullImage(ctx context.Context, imageName string) error {
	reader, err := c.docker.ImagePull(ctx, imageName, types.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}
	defer reader.Close()

	// Drain the reader to complete the pull
	_, err = io.Copy(io.Discard, reader)
	return err
}

// ImageExists checks if an image exists locally
func (c *Client) ImageExists(ctx context.Context, imageName string) bool {
	_, _, err := c.docker.ImageInspectWithRaw(ctx, imageName)
	return err == nil
}

// FindContainerByUUID finds a container by its server UUID label
func (c *Client) FindContainerByUUID(ctx context.Context, uuid string) (*types.Container, error) {
	containers, err := c.docker.ContainerList(ctx, types.ContainerListOptions{
		All: true,
		Filters: filters.NewArgs(
			filters.Arg("label", fmt.Sprintf("roots.server.uuid=%s", uuid)),
		),
	})
	if err != nil {
		return nil, err
	}

	if len(containers) == 0 {
		return nil, nil
	}

	return &containers[0], nil
}

// ListManagedContainers returns all containers managed by Roots
func (c *Client) ListManagedContainers(ctx context.Context) ([]types.Container, error) {
	return c.docker.ContainerList(ctx, types.ContainerListOptions{
		All: true,
		Filters: filters.NewArgs(
			filters.Arg("label", "roots.managed=true"),
		),
	})
}

// Helper to decode stats JSON
func decodeStats(reader io.Reader, stats *types.StatsJSON) error {
	decoder := json.NewDecoder(reader)
	return decoder.Decode(stats)
}

// ImagePruneReport contains the result of pruning images
type ImagePruneReport struct {
	ImagesDeleted  []string `json:"images_deleted"`
	SpaceReclaimed uint64   `json:"space_reclaimed"`
}

// PruneImages removes unused Docker images
func (c *Client) PruneImages(ctx context.Context) (*ImagePruneReport, error) {
	report, err := c.docker.ImagesPrune(ctx, filters.Args{})
	if err != nil {
		return nil, fmt.Errorf("failed to prune images: %w", err)
	}

	deleted := make([]string, 0, len(report.ImagesDeleted))
	for _, img := range report.ImagesDeleted {
		if img.Deleted != "" {
			deleted = append(deleted, img.Deleted)
		} else if img.Untagged != "" {
			deleted = append(deleted, img.Untagged)
		}
	}

	return &ImagePruneReport{
		ImagesDeleted:  deleted,
		SpaceReclaimed: report.SpaceReclaimed,
	}, nil
}

// Calculate CPU usage percent
func calculateCPUPercent(stats *types.StatsJSON) float64 {
	cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage - stats.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stats.CPUStats.SystemUsage - stats.PreCPUStats.SystemUsage)
	cpuCount := float64(stats.CPUStats.OnlineCPUs)

	if cpuCount == 0 {
		cpuCount = float64(len(stats.CPUStats.CPUUsage.PercpuUsage))
	}

	if systemDelta > 0 && cpuDelta > 0 {
		return (cpuDelta / systemDelta) * cpuCount * 100.0
	}

	return 0.0
}
