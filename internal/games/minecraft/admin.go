// Package minecraft provides Minecraft-specific protocol implementations
package minecraft

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ServerAdmin provides an interface for server administration operations.
// This abstraction allows support for different protocols:
// - RCON (all versions)
// - MSMP - Minecraft Server Management Protocol (1.21.9+)
type ServerAdmin interface {
	// ListPlayers returns the list of online players
	ListPlayers() (*PlayersListResponse, error)

	// Kick removes a player from the server
	Kick(player, reason string) (string, error)

	// Ban bans a player from the server
	Ban(player, reason string) (string, error)

	// Pardon unbans a player
	Pardon(player string) (string, error)

	// WhitelistList returns the whitelist
	WhitelistList() ([]string, error)

	// WhitelistAdd adds a player to the whitelist
	WhitelistAdd(player string) (string, error)

	// WhitelistRemove removes a player from the whitelist
	WhitelistRemove(player string) (string, error)

	// WhitelistOn enables the whitelist
	WhitelistOn() (string, error)

	// WhitelistOff disables the whitelist
	WhitelistOff() (string, error)

	// Op gives a player operator status
	Op(player string) (string, error)

	// Deop removes operator status from a player
	Deop(player string) (string, error)

	// Execute runs a raw command (RCON) or is unsupported (MSMP)
	Execute(command string) (string, error)

	// Close closes the connection
	Close() error

	// Protocol returns the protocol name ("rcon" or "msmp")
	Protocol() string
}

// AdminConfig contains configuration for creating a server admin connection
type AdminConfig struct {
	Host string
	Port int // Game port - we may derive RCON/MSMP port from this or use defaults

	// RCON settings
	RCONPort     int
	RCONPassword string

	// MSMP settings (for future use)
	MSMPPort   int
	MSMPSecret string

	// Version info for protocol selection
	ServerVersion string // e.g., "1.21.9" - used to decide RCON vs MSMP
}

// NewServerAdmin creates a ServerAdmin using the appropriate protocol.
// For now, this always returns an RCON client. In the future, it will
// check the server version and use MSMP for 1.21.9+.
func NewServerAdmin(cfg AdminConfig) (ServerAdmin, error) {
	// TODO: Check server version and use MSMP for 1.21.9+
	// For now, always use RCON

	if cfg.RCONPassword == "" {
		return nil, fmt.Errorf("RCON password not configured")
	}

	rconPort := cfg.RCONPort
	if rconPort == 0 {
		rconPort = 25575 // default RCON port
	}

	return NewRCONClient(cfg.Host, rconPort, cfg.RCONPassword)
}

// ParseVersion parses a Minecraft version string and returns major, minor, patch
// Examples: "1.21.9" -> (1, 21, 9), "1.20" -> (1, 20, 0)
func ParseVersion(version string) (major, minor, patch int, err error) {
	// Remove any prefix like "Paper " or "Spigot "
	re := regexp.MustCompile(`\d+\.\d+(?:\.\d+)?`)
	match := re.FindString(version)
	if match == "" {
		return 0, 0, 0, fmt.Errorf("could not parse version: %s", version)
	}

	parts := strings.Split(match, ".")
	if len(parts) < 2 {
		return 0, 0, 0, fmt.Errorf("invalid version format: %s", version)
	}

	major, _ = strconv.Atoi(parts[0])
	minor, _ = strconv.Atoi(parts[1])
	if len(parts) > 2 {
		patch, _ = strconv.Atoi(parts[2])
	}

	return major, minor, patch, nil
}

// SupportsMSMP returns true if the given version supports MSMP (1.21.9+)
func SupportsMSMP(version string) bool {
	major, minor, patch, err := ParseVersion(version)
	if err != nil {
		return false
	}

	// MSMP was added in 1.21.9
	if major > 1 {
		return true
	}
	if major == 1 && minor > 21 {
		return true
	}
	if major == 1 && minor == 21 && patch >= 9 {
		return true
	}
	return false
}

// Ensure RCONClient implements ServerAdmin
var _ ServerAdmin = (*RCONClient)(nil)

// Protocol returns "rcon"
func (c *RCONClient) Protocol() string {
	return "rcon"
}
