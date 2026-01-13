package minecraft

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/sproutpanel/roots/internal/games"
)

// Adapter implements games.GameAdapter for Minecraft servers
type Adapter struct {
	*games.BaseAdapter
	logger *slog.Logger

	// Connection pools
	rconConns     map[string]*RCONClient
	rconMu        sync.Mutex
	mgmtConns     map[string]*ManagementClient
	mgmtMu        sync.Mutex
}

// MinecraftConfig returns the default configuration for Minecraft servers
func MinecraftConfig() *games.GameConfig {
	return &games.GameConfig{
		Type:        games.GameMinecraft,
		DefaultPort: 25565,
		ProtocolPorts: map[string]int{
			"rcon":       25575,
			"management": 25576,
			"query":      25565,
		},
		StateFiles: []string{
			"whitelist.json",
			"ops.json",
			"banned-players.json",
			"banned-ips.json",
		},
		ConfigFile: "server.properties",
		Features: []games.Feature{
			games.FeaturePlayers,
			games.FeatureRCON,
			games.FeatureManagementProtocol,
			games.FeatureGamerules,
			games.FeatureDatapacks,
			games.FeatureMods,
			games.FeaturePlugins,
			games.FeatureProperties,
			games.FeatureWorldManagement,
		},
	}
}

// NewAdapter creates a new Minecraft adapter
func NewAdapter(logger *slog.Logger) *Adapter {
	config := MinecraftConfig()
	return &Adapter{
		BaseAdapter: games.NewBaseAdapter(games.GameMinecraft, config),
		logger:      logger,
		rconConns:   make(map[string]*RCONClient),
		mgmtConns:   make(map[string]*ManagementClient),
	}
}

// GetProtocolClient returns a protocol client for the specified protocol
func (a *Adapter) GetProtocolClient(ctx context.Context, serverCtx *games.ServerContext, protocol string) (games.ProtocolClient, error) {
	switch protocol {
	case "rcon":
		return a.getRCONClient(serverCtx)
	case "management":
		return a.getManagementClient(serverCtx)
	default:
		return nil, games.ErrProtocolNotSupported
	}
}

// getRCONClient returns a persistent RCON connection for the server
func (a *Adapter) getRCONClient(serverCtx *games.ServerContext) (*RCONClient, error) {
	a.rconMu.Lock()
	defer a.rconMu.Unlock()

	if client, ok := a.rconConns[serverCtx.UUID]; ok {
		return client, nil
	}

	// Get RCON configuration from server context
	port := serverCtx.ExtraPorts["rcon"]
	if port == 0 {
		port = 25575
	}

	password, err := GetProperty(serverCtx.DataDir, "rcon.password")
	if err != nil || password == "" {
		return nil, fmt.Errorf("RCON password not configured")
	}

	client, err := NewRCONClient("localhost", port, password)
	if err != nil {
		return nil, err
	}

	a.rconConns[serverCtx.UUID] = client
	return client, nil
}

// getManagementClient returns a persistent Management Protocol connection
func (a *Adapter) getManagementClient(serverCtx *games.ServerContext) (*ManagementClient, error) {
	a.mgmtMu.Lock()
	defer a.mgmtMu.Unlock()

	if client, ok := a.mgmtConns[serverCtx.UUID]; ok {
		return client, nil
	}

	// Get Management configuration from server context
	port := serverCtx.ExtraPorts["management"]
	if port == 0 {
		port = 25576
	}

	secret, err := GetProperty(serverCtx.DataDir, "management-server-secret")
	if err != nil || secret == "" {
		return nil, fmt.Errorf("Management Protocol secret not configured")
	}

	// TLS is disabled for local connections
	client, err := NewManagementClient("localhost", port, secret, false)
	if err != nil {
		return nil, err
	}

	a.mgmtConns[serverCtx.UUID] = client
	return client, nil
}

// CloseConnections closes all protocol connections for a server
func (a *Adapter) CloseConnections(serverCtx *games.ServerContext) {
	a.closeRCONConnection(serverCtx.UUID)
	a.closeManagementConnection(serverCtx.UUID)
}

// closeRCONConnection closes the RCON connection for a server
func (a *Adapter) closeRCONConnection(uuid string) {
	a.rconMu.Lock()
	defer a.rconMu.Unlock()

	if client, ok := a.rconConns[uuid]; ok {
		client.Close()
		delete(a.rconConns, uuid)
	}
}

// closeManagementConnection closes the Management Protocol connection for a server
func (a *Adapter) closeManagementConnection(uuid string) {
	a.mgmtMu.Lock()
	defer a.mgmtMu.Unlock()

	if client, ok := a.mgmtConns[uuid]; ok {
		client.Close()
		delete(a.mgmtConns, uuid)
	}
}

// ListPlayers returns the list of online players
func (a *Adapter) ListPlayers(ctx context.Context, serverCtx *games.ServerContext) (*games.PlayersResponse, error) {
	// Try Management Protocol first (more reliable)
	if mgmt, err := a.getManagementClient(serverCtx); err == nil {
		players, err := mgmt.QueryPlayers()
		if err == nil {
			result := &games.PlayersResponse{
				Online:  len(players),
				Max:     20, // TODO: Get from server properties
				Players: make([]games.PlayerInfo, len(players)),
			}
			for i, p := range players {
				result.Players[i] = games.PlayerInfo{
					Name:   p.Name,
					UUID:   p.UUID,
					Online: true,
				}
			}
			return result, nil
		}
		a.logger.Debug("Management Protocol player query failed, falling back to RCON", "error", err)
	}

	// Fall back to RCON
	rcon, err := a.getRCONClient(serverCtx)
	if err != nil {
		// Fall back to SLP if RCON is not available
		status, err := PingServer("localhost", serverCtx.Port)
		if err != nil {
			return nil, err
		}
		result := &games.PlayersResponse{
			Online:  status.Online,
			Max:     status.Max,
			Players: make([]games.PlayerInfo, len(status.Players)),
		}
		for i, p := range status.Players {
			result.Players[i] = games.PlayerInfo{
				Name:   p.Name,
				UUID:   p.UUID,
				Online: true,
			}
		}
		return result, nil
	}

	list, err := rcon.ListPlayers()
	if err != nil {
		return nil, err
	}

	result := &games.PlayersResponse{
		Online:  list.Online,
		Max:     list.Max,
		Players: make([]games.PlayerInfo, len(list.Players)),
	}
	for i, p := range list.Players {
		result.Players[i] = games.PlayerInfo{
			Name:   p.Name,
			UUID:   p.UUID,
			Online: true,
		}
	}
	return result, nil
}

// KickPlayer kicks a player from the server
func (a *Adapter) KickPlayer(ctx context.Context, serverCtx *games.ServerContext, player, reason string) error {
	// Try Management Protocol first
	if mgmt, err := a.getManagementClient(serverCtx); err == nil {
		if err := mgmt.KickPlayer(player, reason); err == nil {
			return nil
		}
	}

	// Fall back to RCON
	rcon, err := a.getRCONClient(serverCtx)
	if err != nil {
		return err
	}
	_, err = rcon.Kick(player, reason)
	return err
}

// BanPlayer bans a player from the server
func (a *Adapter) BanPlayer(ctx context.Context, serverCtx *games.ServerContext, player, reason string) error {
	// Try Management Protocol first
	if mgmt, err := a.getManagementClient(serverCtx); err == nil {
		if err := mgmt.BanPlayer(player, reason); err == nil {
			return nil
		}
	}

	// Fall back to RCON
	rcon, err := a.getRCONClient(serverCtx)
	if err != nil {
		return err
	}
	_, err = rcon.Ban(player, reason)
	return err
}

// PardonPlayer unbans a player
func (a *Adapter) PardonPlayer(ctx context.Context, serverCtx *games.ServerContext, player string) error {
	// Try Management Protocol first
	if mgmt, err := a.getManagementClient(serverCtx); err == nil {
		if err := mgmt.UnbanPlayer(player); err == nil {
			return nil
		}
	}

	// Fall back to RCON
	rcon, err := a.getRCONClient(serverCtx)
	if err != nil {
		return err
	}
	_, err = rcon.Pardon(player)
	return err
}

// GetBanList returns the list of banned players
func (a *Adapter) GetBanList(ctx context.Context, serverCtx *games.ServerContext) ([]string, error) {
	// Try Management Protocol first
	if mgmt, err := a.getManagementClient(serverCtx); err == nil {
		bans, err := mgmt.QueryBannedPlayers()
		if err == nil {
			result := make([]string, len(bans))
			for i, b := range bans {
				result[i] = b.Player.Name
			}
			return result, nil
		}
	}

	// Fall back to RCON
	rcon, err := a.getRCONClient(serverCtx)
	if err != nil {
		return nil, err
	}
	return rcon.BanList()
}

// GetStatus returns the server status
func (a *Adapter) GetStatus(ctx context.Context, serverCtx *games.ServerContext) (*games.ServerStatus, error) {
	status, err := PingServer("localhost", serverCtx.Port)
	if err != nil {
		return nil, err
	}

	return &games.ServerStatus{
		Online:      true,
		Version:     status.Version,
		MOTD:        status.MOTD,
		PlayerCount: status.Online,
		MaxPlayers:  status.Max,
	}, nil
}

// ParseConfigFile parses server.properties
func (a *Adapter) ParseConfigFile(path string) (map[string]interface{}, error) {
	props, err := ReadPropertiesFile(path)
	if err != nil {
		return nil, err
	}

	result := make(map[string]interface{})
	for k, v := range props {
		result[k] = v
	}
	return result, nil
}

// WriteConfigFile writes server.properties
func (a *Adapter) WriteConfigFile(path string, config map[string]interface{}) error {
	props := make(map[string]string)
	for k, v := range config {
		props[k] = fmt.Sprintf("%v", v)
	}
	return WritePropertiesFile(path, props)
}

// OnInstall is called after server installation
func (a *Adapter) OnInstall(ctx context.Context, serverCtx *games.ServerContext) error {
	// Configure RCON by default
	rconPort := serverCtx.ExtraPorts["rcon"]
	if rconPort == 0 {
		rconPort = 25575
	}
	_, err := ConfigureRCON(serverCtx.DataDir, rconPort, "")
	if err != nil {
		return fmt.Errorf("failed to configure RCON: %w", err)
	}

	// Configure Management Protocol if supported (version check would go here)
	mgmtPort := serverCtx.ExtraPorts["management"]
	if mgmtPort == 0 {
		mgmtPort = 25576
	}
	_, err = ConfigureManagement(serverCtx.DataDir, mgmtPort, "")
	if err != nil {
		a.logger.Warn("Failed to configure Management Protocol", "error", err)
		// Not fatal - RCON is always available
	}

	return nil
}

// OnStop is called when a server is stopped
func (a *Adapter) OnStop(ctx context.Context, serverCtx *games.ServerContext) error {
	a.CloseConnections(serverCtx)
	return nil
}

// Ensure Adapter implements games.GameAdapter
var _ games.GameAdapter = (*Adapter)(nil)
