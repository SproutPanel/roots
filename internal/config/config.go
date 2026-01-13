package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Panel     PanelConfig     `yaml:"panel"`
	Daemon    DaemonConfig    `yaml:"daemon"`
	Docker    DockerConfig    `yaml:"docker"`
	Storage   StorageConfig   `yaml:"storage"`
	SFTP      SFTPConfig      `yaml:"sftp"`
	Resources ResourcesConfig `yaml:"resources"`
	Hytale    HytaleConfig    `yaml:"hytale"`
}

type PanelConfig struct {
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
}

type DaemonConfig struct {
	Host    string    `yaml:"host"`
	Port    int       `yaml:"port"`
	TLS     TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type DockerConfig struct {
	Socket  string `yaml:"socket"`
	Network string `yaml:"network"`
}

type StorageConfig struct {
	Servers string `yaml:"servers"`
	Backups string `yaml:"backups"`
}

type SFTPConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	HostKey string `yaml:"host_key"`
}

type ResourcesConfig struct {
	Memory      string `yaml:"memory"`       // Human-readable memory limit (e.g., "16GB", "8GB")
	Disk        string `yaml:"disk"`         // Human-readable disk limit (e.g., "100GB", "500GB")
	MemoryBytes uint64 `yaml:"-"`            // Parsed memory limit in bytes (internal)
	DiskBytes   uint64 `yaml:"-"`            // Parsed disk limit in bytes (internal)
}

// HytaleConfig stores node-level Hytale authentication and downloader settings
type HytaleConfig struct {
	// OAuth2 credentials for hytale-downloader
	AccessToken     string    `yaml:"access_token,omitempty"`
	RefreshToken    string    `yaml:"refresh_token,omitempty"`
	TokenExpiresAt  time.Time `yaml:"token_expires_at,omitempty"`
	// Docker image for running hytale-downloader (Linux amd64 only)
	DownloaderImage   string `yaml:"downloader_image,omitempty"`
	DownloaderVersion string `yaml:"downloader_version,omitempty"`
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, ".local", "share", "roots")

	return &Config{
		Panel: PanelConfig{
			URL:   "http://localhost:3000",
			Token: "",
		},
		Daemon: DaemonConfig{
			Host: "0.0.0.0",
			Port: 8443,
		},
		Docker: DockerConfig{
			Socket:  getDockerSocket(),
			Network: "roots_network",
		},
		Storage: StorageConfig{
			Servers: filepath.Join(dataDir, "servers"),
			Backups: filepath.Join(dataDir, "backups"),
		},
		SFTP: SFTPConfig{
			Enabled: true,
			Port:    2022,
			HostKey: filepath.Join(home, ".config", "roots", "ssh_host_key"),
		},
	}
}

// getDockerSocket returns the default Docker socket path for the current OS
func getDockerSocket() string {
	// Check for Docker Desktop on macOS
	home, _ := os.UserHomeDir()
	macSocket := filepath.Join(home, ".docker", "run", "docker.sock")
	if _, err := os.Stat(macSocket); err == nil {
		return macSocket
	}

	// Default Linux socket
	return "/var/run/docker.sock"
}

// Load reads config from a YAML file
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	// Expand path
	if path == "" {
		path = "/etc/roots/config.yaml"
	}
	path = expandPath(path)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // Use defaults if no config file
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Parse human-readable resource limits
	if err := cfg.parseResources(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Save writes config to a YAML file
func (c *Config) Save(path string) error {
	path = expandPath(path)

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate checks if the config has all required fields
func (c *Config) Validate() error {
	if c.Panel.URL == "" {
		return fmt.Errorf("panel.url is required")
	}
	if c.Panel.Token == "" {
		return fmt.Errorf("panel.token is required")
	}
	if c.Daemon.Port <= 0 || c.Daemon.Port > 65535 {
		return fmt.Errorf("daemon.port must be between 1 and 65535")
	}
	// Validate TLS config if enabled
	if c.Daemon.TLS.Enabled {
		if c.Daemon.TLS.CertFile == "" {
			return fmt.Errorf("daemon.tls.cert_file is required when TLS is enabled")
		}
		if c.Daemon.TLS.KeyFile == "" {
			return fmt.Errorf("daemon.tls.key_file is required when TLS is enabled")
		}
		// Check if cert and key files exist
		certPath := expandPath(c.Daemon.TLS.CertFile)
		keyPath := expandPath(c.Daemon.TLS.KeyFile)
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			return fmt.Errorf("TLS cert file not found: %s", certPath)
		}
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			return fmt.Errorf("TLS key file not found: %s", keyPath)
		}
	}
	return nil
}

// TLSEnabled returns whether TLS is enabled
func (c *Config) TLSEnabled() bool {
	return c.Daemon.TLS.Enabled
}

// TLSCertPath returns the expanded path to the TLS certificate
func (c *Config) TLSCertPath() string {
	return expandPath(c.Daemon.TLS.CertFile)
}

// TLSKeyPath returns the expanded path to the TLS key
func (c *Config) TLSKeyPath() string {
	return expandPath(c.Daemon.TLS.KeyFile)
}

func expandPath(path string) string {
	if len(path) > 0 && path[0] == '~' {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[1:])
	}
	return path
}

// parseSize parses a human-readable size string (e.g., "16GB", "512MB") to bytes
func parseSize(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}

	s = strings.TrimSpace(strings.ToUpper(s))

	// Match number followed by optional unit
	re := regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB|K|M|G|T)?$`)
	matches := re.FindStringSubmatch(s)
	if matches == nil {
		return 0, fmt.Errorf("invalid size format: %s", s)
	}

	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %s", matches[1])
	}

	unit := matches[2]
	var multiplier uint64 = 1

	switch unit {
	case "B", "":
		multiplier = 1
	case "K", "KB":
		multiplier = 1024
	case "M", "MB":
		multiplier = 1024 * 1024
	case "G", "GB":
		multiplier = 1024 * 1024 * 1024
	case "T", "TB":
		multiplier = 1024 * 1024 * 1024 * 1024
	}

	return uint64(value * float64(multiplier)), nil
}

// parseResources parses human-readable resource limits to bytes
func (c *Config) parseResources() error {
	var err error

	if c.Resources.Memory != "" {
		c.Resources.MemoryBytes, err = parseSize(c.Resources.Memory)
		if err != nil {
			return fmt.Errorf("invalid memory size: %w", err)
		}
	}

	if c.Resources.Disk != "" {
		c.Resources.DiskBytes, err = parseSize(c.Resources.Disk)
		if err != nil {
			return fmt.Errorf("invalid disk size: %w", err)
		}
	}

	return nil
}

// HytaleAuthenticated returns true if the node has valid Hytale OAuth credentials
func (h *HytaleConfig) HasValidCredentials() bool {
	if h.AccessToken == "" {
		return false
	}
	// Check if token has expired (with 5 minute buffer)
	if !h.TokenExpiresAt.IsZero() && time.Now().Add(5*time.Minute).After(h.TokenExpiresAt) {
		return false
	}
	return true
}

// NeedsRefresh returns true if the token should be refreshed soon
func (h *HytaleConfig) NeedsRefresh() bool {
	if h.RefreshToken == "" {
		return false
	}
	// Refresh if token expires within 30 minutes
	if !h.TokenExpiresAt.IsZero() && time.Now().Add(30*time.Minute).After(h.TokenExpiresAt) {
		return true
	}
	return false
}

// ClearCredentials removes all OAuth credentials
func (h *HytaleConfig) ClearCredentials() {
	h.AccessToken = ""
	h.RefreshToken = ""
	h.TokenExpiresAt = time.Time{}
}

// SetCredentials stores new OAuth credentials
func (h *HytaleConfig) SetCredentials(accessToken, refreshToken string, expiresAt time.Time) {
	h.AccessToken = accessToken
	h.RefreshToken = refreshToken
	h.TokenExpiresAt = expiresAt
}
