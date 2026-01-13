package minecraft

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ManagedProperties defines properties that are managed by Sprout and should not be edited by users
var ManagedProperties = map[string]string{
	"server-port":                  "Allocated by Sprout",
	"enable-rcon":                  "Managed for remote administration",
	"rcon.port":                    "Managed for remote administration",
	"rcon.password":                "Managed for remote administration",
	"query.port":                   "Allocated by Sprout",
	"enable-query":                 "Managed for server status",
	"management-server-enabled":    "Managed for remote administration (1.21.9+)",
	"management-server-port":       "Managed for remote administration (1.21.9+)",
	"management-server-secret":     "Managed for remote administration (1.21.9+)",
	"management-server-tls-enabled": "Managed for remote administration (1.21.9+)",
	"management-server-host":       "Managed for remote administration (1.21.9+)",
}

// IsManagedProperty returns true if the property is managed by Sprout
func IsManagedProperty(key string) bool {
	_, ok := ManagedProperties[key]
	return ok
}

// GetManagedPropertyReason returns why a property is managed, or empty string if not managed
func GetManagedPropertyReason(key string) string {
	return ManagedProperties[key]
}

// RCONConfig contains RCON configuration
type RCONConfig struct {
	Enabled  bool
	Port     int
	Password string
}

// GenerateRCONPassword generates a secure random password for RCON
func GenerateRCONPassword() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// ConfigureRCON updates server.properties to enable RCON with the given settings
// If password is empty, generates a random one
func ConfigureRCON(serverDir string, port int, password string) (*RCONConfig, error) {
	propsPath := filepath.Join(serverDir, "server.properties")

	// Generate password if not provided
	if password == "" {
		var err error
		password, err = GenerateRCONPassword()
		if err != nil {
			return nil, fmt.Errorf("failed to generate RCON password: %w", err)
		}
	}

	// Default port
	if port == 0 {
		port = 25575
	}

	// Read existing properties
	props, err := ReadPropertiesFile(propsPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read server.properties: %w", err)
	}
	if props == nil {
		props = make(map[string]string)
	}

	// Set RCON properties
	props["enable-rcon"] = "true"
	props["rcon.port"] = fmt.Sprintf("%d", port)
	props["rcon.password"] = password
	props["broadcast-rcon-to-ops"] = "false" // Don't spam ops with RCON commands

	// Write back
	if err := WritePropertiesFile(propsPath, props); err != nil {
		return nil, fmt.Errorf("failed to write server.properties: %w", err)
	}

	return &RCONConfig{
		Enabled:  true,
		Port:     port,
		Password: password,
	}, nil
}

// ManagementConfig contains Management Protocol configuration
type ManagementConfig struct {
	Enabled bool
	Port    int
	Secret  string
	TLS     bool
}

// GenerateManagementSecret generates a secure random secret for Management Protocol
// Must be exactly 40 alphanumeric characters
func GenerateManagementSecret() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 40

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	for i := range bytes {
		bytes[i] = charset[int(bytes[i])%len(charset)]
	}
	return string(bytes), nil
}

// ConfigureManagement updates server.properties to enable Management Protocol (1.21.9+)
// If secret is empty, generates a random one
// Note: TLS is disabled by default since we connect via localhost and don't have a keystore
func ConfigureManagement(serverDir string, port int, secret string) (*ManagementConfig, error) {
	propsPath := filepath.Join(serverDir, "server.properties")

	// Generate secret if not provided
	if secret == "" {
		var err error
		secret, err = GenerateManagementSecret()
		if err != nil {
			return nil, fmt.Errorf("failed to generate management secret: %w", err)
		}
	}

	// Default port (inside container)
	if port == 0 {
		port = 25576
	}

	// Read existing properties
	props, err := ReadPropertiesFile(propsPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read server.properties: %w", err)
	}
	if props == nil {
		props = make(map[string]string)
	}

	// Set Management Protocol properties
	// TLS disabled - requires keystore setup which we don't have
	// Host set to empty to listen on all interfaces (required for Docker port mapping)
	props["management-server-enabled"] = "true"
	props["management-server-port"] = fmt.Sprintf("%d", port)
	props["management-server-secret"] = secret
	props["management-server-tls-enabled"] = "false"
	props["management-server-host"] = "0.0.0.0" // Listen on all interfaces for Docker access

	// Write back
	if err := WritePropertiesFile(propsPath, props); err != nil {
		return nil, fmt.Errorf("failed to write server.properties: %w", err)
	}

	return &ManagementConfig{
		Enabled: true,
		Port:    port,
		Secret:  secret,
		TLS:     false,
	}, nil
}

// SupportsManagementProtocol checks if a Minecraft version supports the Management Protocol
// Management Protocol was introduced in Minecraft 1.21.9
// Supports both old format (1.21.9) and new format (26.1) after version change
func SupportsManagementProtocol(version string) bool {
	if version == "" {
		return false
	}

	// "latest" always means the newest version, which should support it
	if version == "latest" {
		return true
	}

	// Handle snapshot/pre-release suffixes (e.g., "26.1-snapshot-1" -> "26.1")
	baseVersion := strings.Split(version, "-")[0]

	// Parse version parts
	parts := strings.Split(baseVersion, ".")
	if len(parts) < 2 {
		return false
	}

	// Parse first number
	first := 0
	fmt.Sscanf(parts[0], "%d", &first)

	// New versioning scheme (post 1.21.11): starts with 26+
	// Format: "26.1", "26.1-snapshot-1", etc.
	if first >= 26 {
		return true // All new format versions support it
	}

	// Old versioning scheme: "1.x.y"
	if first != 1 {
		return false // Unknown major version
	}

	// Parse minor version
	minor := 0
	fmt.Sscanf(parts[1], "%d", &minor)
	if minor < 21 {
		return false
	}
	if minor > 21 {
		return true // 1.22+ would support it
	}

	// For 1.21.x, check patch version
	if len(parts) < 3 {
		return false // 1.21.0 doesn't have it
	}

	patch := 0
	fmt.Sscanf(parts[2], "%d", &patch)

	return patch >= 9
}

// EnsureProperty sets a property only if it doesn't exist
func EnsureProperty(serverDir, key, value string) error {
	propsPath := filepath.Join(serverDir, "server.properties")

	props, err := ReadPropertiesFile(propsPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if props == nil {
		props = make(map[string]string)
	}

	// Only set if not already present
	if _, ok := props[key]; !ok {
		props[key] = value
		return WritePropertiesFile(propsPath, props)
	}

	return nil
}

// SetProperty sets a property (overwriting if exists)
func SetProperty(serverDir, key, value string) error {
	propsPath := filepath.Join(serverDir, "server.properties")

	props, err := ReadPropertiesFile(propsPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if props == nil {
		props = make(map[string]string)
	}

	props[key] = value
	return WritePropertiesFile(propsPath, props)
}

// GetProperty gets a property value
func GetProperty(serverDir, key string) (string, error) {
	propsPath := filepath.Join(serverDir, "server.properties")
	props, err := ReadPropertiesFile(propsPath)
	if err != nil {
		return "", err
	}
	return props[key], nil
}

// ReadPropertiesFile reads a Java properties file
func ReadPropertiesFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	props := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split on first = sign
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			props[key] = value
		}
	}

	return props, scanner.Err()
}

// WritePropertiesFile writes a properties file, preserving comments
func WritePropertiesFile(path string, props map[string]string) error {
	// Read original file to preserve comments and order
	var lines []string
	existingKeys := make(map[string]bool)

	if file, err := os.Open(path); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)

			// Keep comments and empty lines
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				lines = append(lines, line)
				continue
			}

			// Update existing properties
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				existingKeys[key] = true
				if val, ok := props[key]; ok {
					lines = append(lines, fmt.Sprintf("%s=%s", key, val))
				} else {
					lines = append(lines, line)
				}
			} else {
				lines = append(lines, line)
			}
		}
		file.Close()
	}

	// Add new properties that weren't in the file
	for key, val := range props {
		if !existingKeys[key] {
			lines = append(lines, fmt.Sprintf("%s=%s", key, val))
		}
	}

	// Write file
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

// PropertiesWithManagedInfo returns properties with management info
type PropertyInfo struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	Managed   bool   `json:"managed"`
	ManagedBy string `json:"managed_by,omitempty"` // Reason if managed
}

// GetPropertiesWithInfo returns all properties with management information
func GetPropertiesWithInfo(serverDir string) ([]PropertyInfo, error) {
	propsPath := filepath.Join(serverDir, "server.properties")
	props, err := ReadPropertiesFile(propsPath)
	if err != nil {
		return nil, err
	}

	var result []PropertyInfo
	for key, value := range props {
		info := PropertyInfo{
			Key:     key,
			Value:   value,
			Managed: IsManagedProperty(key),
		}
		if info.Managed {
			info.ManagedBy = GetManagedPropertyReason(key)
		}
		result = append(result, info)
	}

	return result, nil
}
