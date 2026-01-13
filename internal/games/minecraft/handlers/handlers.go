// Package handlers provides Minecraft-specific HTTP handlers
package handlers

import (
	"context"
	"log/slog"

	"github.com/sproutpanel/roots/internal/games"
	"github.com/sproutpanel/roots/internal/games/minecraft"
)

// ServerProvider provides access to server data and connections
// This interface is implemented by the main ServerManager
type ServerProvider interface {
	// GetServer returns a server by UUID
	GetServer(uuid string) (ServerInfo, bool)

	// GetRCONClient returns a persistent RCON client for a server
	GetRCONClient(uuid string) (*minecraft.RCONClient, error)

	// GetManagementClient returns a persistent Management Protocol client for a server
	GetManagementClient(uuid string) (*minecraft.ManagementClient, error)

	// CloseRCONConnection closes the RCON connection for a server
	CloseRCONConnection(uuid string)

	// GetServerDir returns the directory path for a server
	GetServerDir(uuid string) string

	// ResolvePath resolves and validates a relative path within a server directory
	ResolvePath(serverDir, relativePath string) (string, error)
}

// ServerInfo contains the server information needed by handlers
type ServerInfo struct {
	UUID     string
	Name     string
	GameType games.GameType
	Status   string
}

// MinecraftHandlers provides Minecraft-specific HTTP handlers
type MinecraftHandlers struct {
	provider ServerProvider
	logger   *slog.Logger
}

// NewMinecraftHandlers creates a new MinecraftHandlers instance
func NewMinecraftHandlers(provider ServerProvider, logger *slog.Logger) *MinecraftHandlers {
	return &MinecraftHandlers{
		provider: provider,
		logger:   logger,
	}
}

// requireMinecraftServer checks that the server exists and is a Minecraft server
func (h *MinecraftHandlers) requireMinecraftServer(ctx context.Context, uuid string) (*ServerInfo, error) {
	server, ok := h.provider.GetServer(uuid)
	if !ok {
		return nil, ErrServerNotFound
	}

	if server.GameType != games.GameMinecraft {
		return nil, ErrNotMinecraftServer
	}

	return &server, nil
}

// requireOnlineMinecraftServer also checks that the server is online
func (h *MinecraftHandlers) requireOnlineMinecraftServer(ctx context.Context, uuid string) (*ServerInfo, error) {
	server, err := h.requireMinecraftServer(ctx, uuid)
	if err != nil {
		return nil, err
	}

	if server.Status != "online" {
		return nil, ErrServerNotOnline
	}

	return server, nil
}
