package games

// GameType represents the type of game server
type GameType string

const (
	GameMinecraft GameType = "minecraft"
	GameHytale    GameType = "hytale"
)

// IsValid returns whether this is a valid game type
func (g GameType) IsValid() bool {
	switch g {
	case GameMinecraft, GameHytale:
		return true
	default:
		return false
	}
}

// String returns the string representation of the game type
func (g GameType) String() string {
	return string(g)
}

// GameConfig contains game-specific configuration
type GameConfig struct {
	Type          GameType          `json:"type"`
	DefaultPort   int               `json:"default_port"`
	ProtocolPorts map[string]int    `json:"protocol_ports"` // e.g., {"rcon": 10000, "management": 20000}
	StateFiles    []string          `json:"state_files"`    // e.g., ["whitelist.json", "ops.json"]
	ConfigFile    string            `json:"config_file"`    // e.g., "server.properties"
	Features      []Feature         `json:"features"`
}

// Feature represents a game feature capability
type Feature string

const (
	FeaturePlayers            Feature = "players"
	FeatureRCON               Feature = "rcon"
	FeatureManagementProtocol Feature = "management_protocol"
	FeatureGamerules          Feature = "gamerules"
	FeatureDatapacks          Feature = "datapacks"
	FeatureMods               Feature = "mods"
	FeaturePlugins            Feature = "plugins"
	FeatureProperties         Feature = "properties"
	FeatureWorldManagement    Feature = "world_management"
)

// HasFeature checks if the game config supports a feature
func (c *GameConfig) HasFeature(f Feature) bool {
	for _, feature := range c.Features {
		if feature == f {
			return true
		}
	}
	return false
}

// PlayerInfo represents basic player information across games
type PlayerInfo struct {
	Name   string `json:"name"`
	UUID   string `json:"uuid,omitempty"`
	Online bool   `json:"online"`
}

// PlayersResponse is a generic player list response
type PlayersResponse struct {
	Online  int          `json:"online"`
	Max     int          `json:"max"`
	Players []PlayerInfo `json:"players"`
}

// ServerStatus represents generic server status
type ServerStatus struct {
	Online      bool   `json:"online"`
	Version     string `json:"version,omitempty"`
	MOTD        string `json:"motd,omitempty"`
	PlayerCount int    `json:"player_count"`
	MaxPlayers  int    `json:"max_players"`
}
