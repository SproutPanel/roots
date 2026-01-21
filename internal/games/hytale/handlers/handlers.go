// Package handlers provides Hytale-specific HTTP handlers
package handlers

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/sproutpanel/roots/internal/games"
)

// ServerProvider provides access to server data and connections
// This interface is implemented by the main ServerManager
type ServerProvider interface {
	// GetServer returns a server by UUID
	GetServer(uuid string) (ServerInfo, bool)

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

// HytaleHandlers provides Hytale-specific HTTP handlers
type HytaleHandlers struct {
	provider ServerProvider
	logger   *slog.Logger
}

// NewHytaleHandlers creates a new HytaleHandlers instance
func NewHytaleHandlers(provider ServerProvider, logger *slog.Logger) *HytaleHandlers {
	return &HytaleHandlers{
		provider: provider,
		logger:   logger,
	}
}

// requireHytaleServer checks that the server exists and is a Hytale server
func (h *HytaleHandlers) requireHytaleServer(ctx context.Context, uuid string) (*ServerInfo, error) {
	server, ok := h.provider.GetServer(uuid)
	if !ok {
		return nil, ErrServerNotFound
	}

	if server.GameType != games.GameHytale {
		return nil, ErrNotHytaleServer
	}

	return &server, nil
}

// writeError writes an appropriate HTTP error based on the error type
func (h *HytaleHandlers) writeError(w http.ResponseWriter, err error) {
	switch err {
	case ErrServerNotFound:
		http.Error(w, err.Error(), http.StatusNotFound)
	case ErrNotHytaleServer:
		http.Error(w, err.Error(), http.StatusBadRequest)
	case ErrServerNotOnline:
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
