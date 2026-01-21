package handlers

import "errors"

var (
	// ErrServerNotFound is returned when the server UUID doesn't exist
	ErrServerNotFound = errors.New("server not found")

	// ErrNotHytaleServer is returned when trying to use Hytale features on a non-Hytale server
	ErrNotHytaleServer = errors.New("this feature is only available for Hytale servers")

	// ErrServerNotOnline is returned when the server must be online but isn't
	ErrServerNotOnline = errors.New("server must be online for this operation")
)
