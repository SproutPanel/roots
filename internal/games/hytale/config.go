package hytale

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// SyncServerConfig applies panel settings from the server environment to the
// Hytale config.json at the server root. It must run while the server is
// stopped, since Hytale overwrites config.json changes made while running.
// If config.json doesn't exist yet it does nothing; the server generates it on first boot.
func SyncServerConfig(serverDir string, env map[string]string) error {
	maxPlayers, ok := env["MAX_PLAYERS"]
	if !ok || maxPlayers == "" {
		return nil
	}
	n, err := strconv.Atoi(maxPlayers)
	if err != nil || n < 1 {
		return fmt.Errorf("invalid MAX_PLAYERS %q", maxPlayers)
	}

	path := filepath.Join(serverDir, "config.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read config.json: %w", err)
	}

	// Decode numbers as json.Number so other values round-trip unchanged
	var config map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&config); err != nil {
		return fmt.Errorf("failed to parse config.json: %w", err)
	}

	if current, ok := config["MaxPlayers"].(json.Number); ok && current.String() == strconv.Itoa(n) {
		return nil
	}
	config["MaxPlayers"] = n

	out, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode config.json: %w", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), info.Mode().Perm())
}
