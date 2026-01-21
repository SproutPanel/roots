// Package hytale provides Hytale-specific protocol implementations
package hytale

import (
	"context"
	"log/slog"
	"regexp"

	"github.com/sproutpanel/roots/internal/games"
)

// Adapter implements games.GameAdapter for Hytale servers
type Adapter struct {
	*games.BaseAdapter
	logger *slog.Logger
}

// HytaleConfig returns the default configuration for Hytale servers
func HytaleConfig() *games.GameConfig {
	return &games.GameConfig{
		Type:        games.GameHytale,
		DefaultPort: 5520, // Hytale's default server port
		ProtocolPorts: map[string]int{
			// Hytale may add query/rcon-like protocols in the future
		},
		StateFiles: []string{
			"whitelist.json",
			"bans.json",
			"permissions.json",
		},
		ConfigFile: "config.json",
		Features: []games.Feature{
			games.FeaturePlayers, // Basic player management via console
			games.FeatureMods,    // Mod support via /mods directory
		},
	}
}

// Console event types
type ConsoleEventType string

const (
	EventAuthPrompt   ConsoleEventType = "auth_prompt"
	EventAuthSuccess  ConsoleEventType = "auth_success"
	EventAuthFailed   ConsoleEventType = "auth_failed"
	EventPlayerJoin   ConsoleEventType = "player_join"
	EventPlayerLeave  ConsoleEventType = "player_leave"
	EventServerReady  ConsoleEventType = "server_ready"
	EventUnknown      ConsoleEventType = "unknown"
)

// ConsoleEvent represents a parsed console output event
type ConsoleEvent struct {
	Type    ConsoleEventType `json:"type"`
	Raw     string           `json:"raw"`
	URL     string           `json:"url,omitempty"`      // For auth_prompt
	Code    string           `json:"code,omitempty"`     // For auth_prompt (device code)
	Player  string           `json:"player,omitempty"`   // For player events
	Message string           `json:"message,omitempty"`  // Additional context
}

// Console output patterns
var (
	// Pattern: "Visit https://accounts.hytale.com/device and enter code: XXXX-YYYY" (single line)
	// The code can be:
	//   - 8 alphanumeric chars (e.g., UCsd9vaU)
	//   - XXXX-YYYY format (e.g., ABCD-1234)
	authPromptPattern = regexp.MustCompile(`(?i)(?:visit|URL)[:\s]*(https?://[^\s]+)[^\n]*(?:enter\s+)?code[:\s]*([A-Za-z0-9]{4,12}(?:-[A-Za-z0-9]{4})?)`)

	// Multi-line patterns - URL might be on its own line
	// Matches standalone Hytale OAuth URLs like:
	//   https://oauth.accounts.hytale.com/oauth2/device/verify?user_code=y6CiAccs
	//   https://oauth.accounts.hytale.com/oauth2/device/verify
	authURLPattern = regexp.MustCompile(`(https?://[^\s]*hytale\.com[^\s]*)`)

	// Matches "Authorization code: xxx" or just a code with user_code param in URL
	authCodePattern   = regexp.MustCompile(`(?i)(?:authorization\s+)?code[:\s]*([A-Za-z0-9]{4,12}(?:-[A-Za-z0-9]{4})?)`)
	authURLCodePattern = regexp.MustCompile(`[?&]user_code=([A-Za-z0-9]{4,12}(?:-[A-Za-z0-9]{4})?)`)

	// Auth success/failure patterns
	authSuccessPattern = regexp.MustCompile(`(?i)authentication\s+successful`)
	authFailedPattern  = regexp.MustCompile(`(?i)authentication\s+(?:failed|error|expired)`)

	// Player patterns (guessing based on common formats)
	playerJoinPattern  = regexp.MustCompile(`(?i)player\s+(\w+)\s+(?:joined|connected)`)
	playerLeavePattern = regexp.MustCompile(`(?i)player\s+(\w+)\s+(?:left|disconnected)`)

	// Server ready pattern
	serverReadyPattern = regexp.MustCompile(`(?i)server\s+(?:started|ready|listening)\s+on\s+port\s+(\d+)`)
)

// NewAdapter creates a new Hytale adapter
func NewAdapter(logger *slog.Logger) *Adapter {
	config := HytaleConfig()
	return &Adapter{
		BaseAdapter: games.NewBaseAdapter(games.GameHytale, config),
		logger:      logger,
	}
}

// GetProtocolClient returns a protocol client for the specified protocol
// TBD - Hytale protocols are not yet known
func (a *Adapter) GetProtocolClient(ctx context.Context, serverCtx *games.ServerContext, protocol string) (games.ProtocolClient, error) {
	return nil, games.ErrProtocolNotSupported
}

// CloseConnections closes all protocol connections for a server
func (a *Adapter) CloseConnections(serverCtx *games.ServerContext) {
	// TBD - no connections to close yet
}

// ListPlayers returns the list of online players
// TBD - player query protocol unknown
func (a *Adapter) ListPlayers(ctx context.Context, serverCtx *games.ServerContext) (*games.PlayersResponse, error) {
	a.logger.Warn("Hytale player listing not yet implemented")
	return &games.PlayersResponse{
		Online:  0,
		Max:     0,
		Players: []games.PlayerInfo{},
	}, nil
}

// KickPlayer kicks a player from the server
// TBD - admin protocol unknown
func (a *Adapter) KickPlayer(ctx context.Context, serverCtx *games.ServerContext, player, reason string) error {
	a.logger.Warn("Hytale kick not yet implemented")
	return games.ErrFeatureNotSupported
}

// BanPlayer bans a player from the server
// TBD - admin protocol unknown
func (a *Adapter) BanPlayer(ctx context.Context, serverCtx *games.ServerContext, player, reason string) error {
	a.logger.Warn("Hytale ban not yet implemented")
	return games.ErrFeatureNotSupported
}

// PardonPlayer unbans a player
// TBD - admin protocol unknown
func (a *Adapter) PardonPlayer(ctx context.Context, serverCtx *games.ServerContext, player string) error {
	a.logger.Warn("Hytale pardon not yet implemented")
	return games.ErrFeatureNotSupported
}

// GetBanList returns the list of banned players
// TBD - admin protocol unknown
func (a *Adapter) GetBanList(ctx context.Context, serverCtx *games.ServerContext) ([]string, error) {
	a.logger.Warn("Hytale ban list not yet implemented")
	return nil, games.ErrFeatureNotSupported
}

// GetStatus returns the server status
// TBD - query protocol unknown
func (a *Adapter) GetStatus(ctx context.Context, serverCtx *games.ServerContext) (*games.ServerStatus, error) {
	a.logger.Warn("Hytale status not yet implemented")
	return &games.ServerStatus{
		Online:      false,
		Version:     "unknown",
		MOTD:        "",
		PlayerCount: 0,
		MaxPlayers:  0,
	}, nil
}

// ParseConfigFile parses Hytale configuration
// TBD - config format unknown
func (a *Adapter) ParseConfigFile(path string) (map[string]interface{}, error) {
	a.logger.Warn("Hytale config parsing not yet implemented")
	return nil, games.ErrFeatureNotSupported
}

// WriteConfigFile writes Hytale configuration
// TBD - config format unknown
func (a *Adapter) WriteConfigFile(path string, config map[string]interface{}) error {
	a.logger.Warn("Hytale config writing not yet implemented")
	return games.ErrFeatureNotSupported
}

// OnInstall is called after server installation
func (a *Adapter) OnInstall(ctx context.Context, serverCtx *games.ServerContext) error {
	a.logger.Info("Hytale server installed", "uuid", serverCtx.UUID)
	// TBD - any post-install setup
	return nil
}

// OnStop is called when a server is stopped
func (a *Adapter) OnStop(ctx context.Context, serverCtx *games.ServerContext) error {
	a.CloseConnections(serverCtx)
	return nil
}

// ParseConsoleLine parses a single line of Hytale server console output
// and returns a structured event if the line matches a known pattern.
// This is used to detect auth prompts, player events, and server status.
func (a *Adapter) ParseConsoleLine(line string) *ConsoleEvent {
	return ParseConsoleLine(line)
}

// ParseConsoleLine is a standalone function for parsing console output
// Can be used without an adapter instance (e.g., during installation)
func ParseConsoleLine(line string) *ConsoleEvent {
	// Check for auth prompt (single line format)
	if matches := authPromptPattern.FindStringSubmatch(line); len(matches) == 3 {
		return &ConsoleEvent{
			Type: EventAuthPrompt,
			Raw:  line,
			URL:  matches[1],
			Code: matches[2],
		}
	}

	// Check for auth URL (may be multi-line, track separately)
	// Also try to extract user_code from URL query param if present
	if matches := authURLPattern.FindStringSubmatch(line); len(matches) == 2 {
		url := matches[1]
		code := ""
		// Try to extract user_code from URL (e.g., ?user_code=y6CiAccs)
		if codeMatches := authURLCodePattern.FindStringSubmatch(url); len(codeMatches) == 2 {
			code = codeMatches[1]
		}
		return &ConsoleEvent{
			Type: EventAuthPrompt,
			Raw:  line,
			URL:  url,
			Code: code, // May be empty if not in URL - caller should look for code in subsequent lines
		}
	}

	// Check for auth code alone (follow-up to URL line)
	if matches := authCodePattern.FindStringSubmatch(line); len(matches) == 2 {
		return &ConsoleEvent{
			Type: EventAuthPrompt,
			Raw:  line,
			Code: matches[1],
			// URL will be empty - caller should combine with previous URL
		}
	}

	// Check for auth success
	if authSuccessPattern.MatchString(line) {
		return &ConsoleEvent{
			Type:    EventAuthSuccess,
			Raw:     line,
			Message: "Authentication successful",
		}
	}

	// Check for auth failure
	if authFailedPattern.MatchString(line) {
		return &ConsoleEvent{
			Type:    EventAuthFailed,
			Raw:     line,
			Message: "Authentication failed",
		}
	}

	// Check for player join
	if matches := playerJoinPattern.FindStringSubmatch(line); len(matches) == 2 {
		return &ConsoleEvent{
			Type:   EventPlayerJoin,
			Raw:    line,
			Player: matches[1],
		}
	}

	// Check for player leave
	if matches := playerLeavePattern.FindStringSubmatch(line); len(matches) == 2 {
		return &ConsoleEvent{
			Type:   EventPlayerLeave,
			Raw:    line,
			Player: matches[1],
		}
	}

	// Check for server ready
	if matches := serverReadyPattern.FindStringSubmatch(line); len(matches) >= 1 {
		return &ConsoleEvent{
			Type:    EventServerReady,
			Raw:     line,
			Message: "Server is ready",
		}
	}

	return nil
}

// AuthPromptTracker helps combine multi-line auth prompts into a single event
type AuthPromptTracker struct {
	pendingURL  string
	pendingCode string
}

// ProcessLine processes a line and returns a complete auth event if found
func (t *AuthPromptTracker) ProcessLine(line string) *ConsoleEvent {
	event := ParseConsoleLine(line)
	if event == nil {
		return nil
	}

	// Not an auth event, return as-is
	if event.Type != EventAuthPrompt {
		return event
	}

	// Track URL if we got one
	if event.URL != "" {
		t.pendingURL = event.URL
	}

	// Track code if we got one
	if event.Code != "" {
		t.pendingCode = event.Code
	}

	// If we have both, return complete event and reset
	if t.pendingURL != "" && t.pendingCode != "" {
		completeEvent := &ConsoleEvent{
			Type: EventAuthPrompt,
			Raw:  line,
			URL:  t.pendingURL,
			Code: t.pendingCode,
		}
		t.pendingURL = ""
		t.pendingCode = ""
		return completeEvent
	}

	// Incomplete auth prompt - don't emit yet
	return nil
}

// Reset clears any pending state
func (t *AuthPromptTracker) Reset() {
	t.pendingURL = ""
	t.pendingCode = ""
}

// Ensure Adapter implements games.GameAdapter
var _ games.GameAdapter = (*Adapter)(nil)
