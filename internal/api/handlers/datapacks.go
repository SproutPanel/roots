package handlers

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// calculateDatapackHash calculates SHA-512 hash of a datapack file
func calculateDatapackHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha512.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// DownloadDatapackRequest is the request body for downloading a datapack
type DownloadDatapackRequest struct {
	URL          string `json:"url"`
	Filename     string `json:"filename"`
	WorldName    string `json:"world_name,omitempty"` // defaults to "world"
	ExpectedHash string `json:"expected_hash,omitempty"`
}

// DownloadDatapackResponse is the response after downloading
type DownloadDatapackResponse struct {
	Path     string `json:"path"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	Hash     string `json:"hash"`
}

// DatapackInfo represents information about an installed datapack
type DatapackInfo struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	Hash     string    `json:"hash"`
	IsDir    bool      `json:"is_dir"` // datapacks can be folders or zips
}

// ListDatapacks handles GET /api/servers/{uuid}/datapacks
// Lists all datapacks in the world's datapacks directory
func (sm *ServerManager) ListDatapacks(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	sm.mu.RLock()
	_, ok := sm.servers[uuid]
	sm.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Get world name from query or default to "world"
	worldName := r.URL.Query().Get("world")
	if worldName == "" {
		worldName = sm.getWorldName(uuid)
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)
	datapacksDir := filepath.Join(serverDir, worldName, "datapacks")

	// Check if datapacks directory exists
	if _, err := os.Stat(datapacksDir); os.IsNotExist(err) {
		// Return empty list if datapacks directory doesn't exist
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]DatapackInfo{})
		return
	}

	entries, err := os.ReadDir(datapacksDir)
	if err != nil {
		sm.logger.Error("Failed to read datapacks directory", "error", err)
		http.Error(w, "Failed to read datapacks directory", http.StatusInternalServerError)
		return
	}

	datapacks := make([]DatapackInfo, 0)

	for _, entry := range entries {
		name := entry.Name()

		// Skip hidden files
		if strings.HasPrefix(name, ".") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		fullPath := filepath.Join(datapacksDir, name)
		relativePath := "/" + worldName + "/datapacks/" + name

		dp := DatapackInfo{
			Name:     name,
			Path:     relativePath,
			Size:     info.Size(),
			Modified: info.ModTime(),
			IsDir:    entry.IsDir(),
		}

		// Calculate hash for zip files
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(name), ".zip") {
			if hash, err := calculateDatapackHash(fullPath); err == nil {
				dp.Hash = hash
			}
		}

		datapacks = append(datapacks, dp)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(datapacks)
}

// DownloadDatapack handles POST /api/servers/{uuid}/datapacks/download
// Downloads a datapack to the world's datapacks directory
func (sm *ServerManager) DownloadDatapack(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	sm.mu.RLock()
	_, ok := sm.servers[uuid]
	sm.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	var req DownloadDatapackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.URL == "" || req.Filename == "" {
		http.Error(w, "url and filename are required", http.StatusBadRequest)
		return
	}

	// Default world name
	worldName := req.WorldName
	if worldName == "" {
		worldName = sm.getWorldName(uuid)
	}

	// Validate filename ends with .zip
	if !strings.HasSuffix(strings.ToLower(req.Filename), ".zip") {
		http.Error(w, "filename must end with .zip", http.StatusBadRequest)
		return
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)
	datapacksDir := filepath.Join(serverDir, worldName, "datapacks")

	// Create datapacks directory if it doesn't exist
	if err := os.MkdirAll(datapacksDir, 0755); err != nil {
		sm.logger.Error("Failed to create datapacks directory", "error", err, "path", datapacksDir)
		http.Error(w, "Failed to create datapacks directory", http.StatusInternalServerError)
		return
	}

	destPath := filepath.Join(datapacksDir, req.Filename)

	// Download the file
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(req.URL)
	if err != nil {
		sm.logger.Error("Failed to download datapack", "error", err, "url", req.URL)
		http.Error(w, fmt.Sprintf("Failed to download: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		sm.logger.Error("Download failed", "status", resp.StatusCode, "url", req.URL)
		http.Error(w, fmt.Sprintf("Download failed with status %d", resp.StatusCode), http.StatusBadGateway)
		return
	}

	// Create destination file
	outFile, err := os.Create(destPath)
	if err != nil {
		sm.logger.Error("Failed to create file", "error", err, "path", destPath)
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer outFile.Close()

	// Copy with hash calculation
	hasher := sha512.New()
	writer := io.MultiWriter(outFile, hasher)

	size, err := io.Copy(writer, resp.Body)
	if err != nil {
		os.Remove(destPath)
		sm.logger.Error("Failed to write file", "error", err)
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
		return
	}

	hash := hex.EncodeToString(hasher.Sum(nil))

	// Verify hash if provided
	if req.ExpectedHash != "" && hash != req.ExpectedHash {
		os.Remove(destPath)
		sm.logger.Error("Hash mismatch", "expected", req.ExpectedHash, "got", hash)
		http.Error(w, "Hash verification failed", http.StatusBadRequest)
		return
	}

	relativePath := "/" + worldName + "/datapacks/" + req.Filename

	sm.logger.Info("Datapack downloaded", "path", relativePath, "size", size)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DownloadDatapackResponse{
		Path:     relativePath,
		Filename: req.Filename,
		Size:     size,
		Hash:     hash,
	})
}

// DeleteDatapack handles DELETE /api/servers/{uuid}/datapacks
// Deletes a datapack from the world's datapacks directory
func (sm *ServerManager) DeleteDatapack(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	sm.mu.RLock()
	_, ok := sm.servers[uuid]
	sm.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	path := r.URL.Query().Get("path")
	if path == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	// Resolve and validate path
	fullPath, err := sm.resolvePath(serverDir, path)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Ensure path is within a datapacks directory
	if !strings.Contains(fullPath, "/datapacks/") {
		http.Error(w, "Path must be within a datapacks directory", http.StatusBadRequest)
		return
	}

	// Check if file/dir exists
	info, err := os.Stat(fullPath)
	if os.IsNotExist(err) {
		http.Error(w, "Datapack not found", http.StatusNotFound)
		return
	}

	// Remove file or directory
	if info.IsDir() {
		err = os.RemoveAll(fullPath)
	} else {
		err = os.Remove(fullPath)
	}

	if err != nil {
		sm.logger.Error("Failed to delete datapack", "error", err, "path", path)
		http.Error(w, "Failed to delete datapack", http.StatusInternalServerError)
		return
	}

	sm.logger.Info("Datapack deleted", "path", path)
	w.WriteHeader(http.StatusNoContent)
}

// getWorldName reads the level-name from server.properties or returns "world"
func (sm *ServerManager) getWorldName(uuid string) string {
	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)
	propsPath := filepath.Join(serverDir, "server.properties")

	props, err := parsePropertiesFile(propsPath)
	if err != nil {
		return "world"
	}

	if name, ok := props["level-name"]; ok && name != "" {
		return name
	}

	return "world"
}
