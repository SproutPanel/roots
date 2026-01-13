package games

import (
	"context"
	"log/slog"
)

// ProtocolClient represents a connection to a game server protocol (RCON, Management, etc.)
type ProtocolClient interface {
	// Execute sends a command and returns the response
	Execute(command string) (string, error)
	// Close closes the protocol connection
	Close() error
}

// ServerContext provides server information to adapters
type ServerContext struct {
	UUID      string
	Name      string
	DataDir   string            // Path to server data directory
	Port      int               // Main game port
	ExtraPorts map[string]int   // Additional ports (rcon, management, etc.)
	Logger    *slog.Logger
}

// GameAdapter defines the interface for game-specific functionality
type GameAdapter interface {
	// Identity
	Type() GameType
	Config() *GameConfig

	// Lifecycle hooks
	OnInstall(ctx context.Context, serverCtx *ServerContext) error
	OnStart(ctx context.Context, serverCtx *ServerContext) error
	OnStop(ctx context.Context, serverCtx *ServerContext) error

	// Protocol connections
	GetProtocolClient(ctx context.Context, serverCtx *ServerContext, protocol string) (ProtocolClient, error)
	CloseConnections(serverCtx *ServerContext)

	// Player management (if supported)
	ListPlayers(ctx context.Context, serverCtx *ServerContext) (*PlayersResponse, error)
	KickPlayer(ctx context.Context, serverCtx *ServerContext, player, reason string) error
	BanPlayer(ctx context.Context, serverCtx *ServerContext, player, reason string) error
	PardonPlayer(ctx context.Context, serverCtx *ServerContext, player string) error
	GetBanList(ctx context.Context, serverCtx *ServerContext) ([]string, error)

	// Server status
	GetStatus(ctx context.Context, serverCtx *ServerContext) (*ServerStatus, error)

	// Configuration
	ParseConfigFile(path string) (map[string]interface{}, error)
	WriteConfigFile(path string, config map[string]interface{}) error

	// Feature checks
	SupportsFeature(feature Feature) bool
}

// BaseAdapter provides default implementations for optional methods
type BaseAdapter struct {
	gameType   GameType
	gameConfig *GameConfig
}

// NewBaseAdapter creates a new base adapter
func NewBaseAdapter(gameType GameType, config *GameConfig) *BaseAdapter {
	return &BaseAdapter{
		gameType:   gameType,
		gameConfig: config,
	}
}

// Type returns the game type
func (a *BaseAdapter) Type() GameType {
	return a.gameType
}

// Config returns the game configuration
func (a *BaseAdapter) Config() *GameConfig {
	return a.gameConfig
}

// SupportsFeature checks if a feature is supported
func (a *BaseAdapter) SupportsFeature(feature Feature) bool {
	return a.gameConfig.HasFeature(feature)
}

// OnInstall is a no-op by default
func (a *BaseAdapter) OnInstall(ctx context.Context, serverCtx *ServerContext) error {
	return nil
}

// OnStart is a no-op by default
func (a *BaseAdapter) OnStart(ctx context.Context, serverCtx *ServerContext) error {
	return nil
}

// OnStop is a no-op by default
func (a *BaseAdapter) OnStop(ctx context.Context, serverCtx *ServerContext) error {
	return nil
}

// GetProtocolClient returns an error by default (no protocol support)
func (a *BaseAdapter) GetProtocolClient(ctx context.Context, serverCtx *ServerContext, protocol string) (ProtocolClient, error) {
	return nil, ErrProtocolNotSupported
}

// CloseConnections is a no-op by default
func (a *BaseAdapter) CloseConnections(serverCtx *ServerContext) {}

// ListPlayers returns an error by default
func (a *BaseAdapter) ListPlayers(ctx context.Context, serverCtx *ServerContext) (*PlayersResponse, error) {
	return nil, ErrFeatureNotSupported
}

// KickPlayer returns an error by default
func (a *BaseAdapter) KickPlayer(ctx context.Context, serverCtx *ServerContext, player, reason string) error {
	return ErrFeatureNotSupported
}

// BanPlayer returns an error by default
func (a *BaseAdapter) BanPlayer(ctx context.Context, serverCtx *ServerContext, player, reason string) error {
	return ErrFeatureNotSupported
}

// PardonPlayer returns an error by default
func (a *BaseAdapter) PardonPlayer(ctx context.Context, serverCtx *ServerContext, player string) error {
	return ErrFeatureNotSupported
}

// GetBanList returns an error by default
func (a *BaseAdapter) GetBanList(ctx context.Context, serverCtx *ServerContext) ([]string, error) {
	return nil, ErrFeatureNotSupported
}

// GetStatus returns an error by default
func (a *BaseAdapter) GetStatus(ctx context.Context, serverCtx *ServerContext) (*ServerStatus, error) {
	return nil, ErrFeatureNotSupported
}

// ParseConfigFile returns an error by default
func (a *BaseAdapter) ParseConfigFile(path string) (map[string]interface{}, error) {
	return nil, ErrFeatureNotSupported
}

// WriteConfigFile returns an error by default
func (a *BaseAdapter) WriteConfigFile(path string, config map[string]interface{}) error {
	return ErrFeatureNotSupported
}
