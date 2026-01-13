// Package version provides version information for the Roots daemon.
// The version can be overridden at build time using ldflags:
//
//	go build -ldflags "-X github.com/sproutpanel/roots/internal/version.Version=1.0.0"
package version

// Version is the current version of Roots.
// This can be overridden at build time using ldflags.
var Version = "0.1.8"

// GetVersion returns the current version string.
func GetVersion() string {
	return Version
}
