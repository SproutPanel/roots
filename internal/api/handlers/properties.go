package handlers

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/sproutpanel/roots/internal/games/minecraft"
)

// ServerProperties represents parsed server.properties
type ServerProperties map[string]string

// WorldInfo contains information about the server's world folder
type WorldInfo struct {
	WorldName     string `json:"world_name"`
	DatapacksPath string `json:"datapacks_path"`
	Exists        bool   `json:"exists"`
}

// GetProperties handles GET /api/servers/{uuid}/properties
// Returns the parsed server.properties file as JSON
func (sm *ServerManager) GetProperties(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	sm.mu.RLock()
	_, ok := sm.servers[uuid]
	sm.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)
	propsPath := filepath.Join(serverDir, "server.properties")

	props, err := parsePropertiesFile(propsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty properties if file doesn't exist
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ServerProperties{})
			return
		}
		sm.logger.Error("Failed to read server.properties", "error", err)
		http.Error(w, "Failed to read server.properties", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(props)
}

// PropertyWithInfo represents a property with management information
type PropertyWithInfo struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	Managed   bool   `json:"managed"`
	ManagedBy string `json:"managed_by,omitempty"`
}

// PropertiesInfoResponse is the response for properties with management info
type PropertiesInfoResponse struct {
	Properties       []PropertyWithInfo `json:"properties"`
	ManagedKeys      []string           `json:"managed_keys"`
}

// GetPropertiesWithInfo handles GET /api/servers/{uuid}/properties/info
// Returns properties with information about which are managed by Sprout
func (sm *ServerManager) GetPropertiesWithInfo(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	sm.mu.RLock()
	_, ok := sm.servers[uuid]
	sm.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)
	propsPath := filepath.Join(serverDir, "server.properties")

	props, err := parsePropertiesFile(propsPath)
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(PropertiesInfoResponse{
				Properties:  []PropertyWithInfo{},
				ManagedKeys: getManagedKeys(),
			})
			return
		}
		sm.logger.Error("Failed to read server.properties", "error", err)
		http.Error(w, "Failed to read server.properties", http.StatusInternalServerError)
		return
	}

	var propsWithInfo []PropertyWithInfo
	for key, value := range props {
		info := PropertyWithInfo{
			Key:     key,
			Value:   value,
			Managed: minecraft.IsManagedProperty(key),
		}
		if info.Managed {
			info.ManagedBy = minecraft.GetManagedPropertyReason(key)
		}
		propsWithInfo = append(propsWithInfo, info)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(PropertiesInfoResponse{
		Properties:  propsWithInfo,
		ManagedKeys: getManagedKeys(),
	})
}

// getManagedKeys returns a list of all managed property keys
func getManagedKeys() []string {
	keys := make([]string, 0, len(minecraft.ManagedProperties))
	for key := range minecraft.ManagedProperties {
		keys = append(keys, key)
	}
	return keys
}

// GetWorldInfo handles GET /api/servers/{uuid}/world-info
// Returns information about the world folder including datapacks path
func (sm *ServerManager) GetWorldInfo(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	sm.mu.RLock()
	_, ok := sm.servers[uuid]
	sm.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)
	propsPath := filepath.Join(serverDir, "server.properties")

	// Default world name
	worldName := "world"

	// Try to read level-name from server.properties
	props, err := parsePropertiesFile(propsPath)
	if err == nil {
		if name, ok := props["level-name"]; ok && name != "" {
			worldName = name
		}
	}

	// Check if world folder exists
	worldPath := filepath.Join(serverDir, worldName)
	datapacksPath := filepath.Join(worldPath, "datapacks")

	exists := false
	if _, err := os.Stat(worldPath); err == nil {
		exists = true
	}

	info := WorldInfo{
		WorldName:     worldName,
		DatapacksPath: "/" + worldName + "/datapacks",
		Exists:        exists,
	}

	// Create datapacks directory if world exists but datapacks folder doesn't
	if exists {
		if _, err := os.Stat(datapacksPath); os.IsNotExist(err) {
			os.MkdirAll(datapacksPath, 0755)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// parsePropertiesFile parses a Java properties file
func parsePropertiesFile(path string) (ServerProperties, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	props := make(ServerProperties)
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

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return props, nil
}
