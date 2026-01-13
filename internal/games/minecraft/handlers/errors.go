package handlers

import "errors"

var (
	// ErrServerNotFound is returned when the server UUID doesn't exist
	ErrServerNotFound = errors.New("server not found")

	// ErrNotMinecraftServer is returned when trying to use Minecraft features on a non-Minecraft server
	ErrNotMinecraftServer = errors.New("this feature is only available for Minecraft servers")

	// ErrServerNotOnline is returned when the server must be online but isn't
	ErrServerNotOnline = errors.New("server must be online for this operation")

	// ErrRCONNotAvailable is returned when RCON is not configured or unreachable
	ErrRCONNotAvailable = errors.New("RCON is not available for this server")

	// ErrManagementNotAvailable is returned when Management Protocol is not available
	ErrManagementNotAvailable = errors.New("Management Protocol is not available (requires Minecraft 1.21.9+)")
)
