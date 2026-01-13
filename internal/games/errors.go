package games

import "errors"

var (
	// ErrGameNotFound is returned when a game type is not registered
	ErrGameNotFound = errors.New("game type not found")

	// ErrFeatureNotSupported is returned when a feature is not supported by the game
	ErrFeatureNotSupported = errors.New("feature not supported by this game")

	// ErrProtocolNotSupported is returned when a protocol is not supported
	ErrProtocolNotSupported = errors.New("protocol not supported by this game")

	// ErrServerOffline is returned when the server is not online
	ErrServerOffline = errors.New("server is not online")

	// ErrConnectionFailed is returned when a protocol connection fails
	ErrConnectionFailed = errors.New("failed to connect to server")
)
