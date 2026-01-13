package handlers

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// DownloadModRequest is the request body for downloading a mod
type DownloadModRequest struct {
	URL           string `json:"url"`
	Filename      string `json:"filename"`
	Destination   string `json:"destination"` // "/mods" or "/plugins"
	ExpectedHash  string `json:"expected_hash,omitempty"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"` // "sha512" or "sha1"
}

// DownloadModResponse is the response after downloading
type DownloadModResponse struct {
	Path     string `json:"path"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	Hash     string `json:"hash"`
}

// ModFileInfo represents information about an installed mod file
type ModFileInfo struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	Hash     string    `json:"hash"`
}

// ToggleModRequest is the request body for enabling/disabling a mod
type ToggleModRequest struct {
	Path   string `json:"path"`   // Current file path
	Enable bool   `json:"enable"` // true to enable, false to disable
}

// ToggleModResponse is the response after toggling a mod
type ToggleModResponse struct {
	Path     string `json:"path"`     // New file path
	Disabled bool   `json:"disabled"` // Current disabled state
}

// BackupModRequest is the request body for backing up a mod before update
type BackupModRequest struct {
	Path string `json:"path"` // Current file path to backup
}

// BackupModResponse is the response after backing up a mod
type BackupModResponse struct {
	BackupPath string `json:"backup_path"`
	Hash       string `json:"hash"`
}

// RestoreModRequest is the request body for restoring a mod from backup
type RestoreModRequest struct {
	BackupPath  string `json:"backup_path"`  // Path to the backup file
	RestorePath string `json:"restore_path"` // Path to restore to
}

// RestoreModResponse is the response after restoring a mod
type RestoreModResponse struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
	Size int64  `json:"size"`
}

// ListMods handles GET /api/servers/{uuid}/minecraft/mods
func (h *MinecraftHandlers) ListMods(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")
	modType := r.URL.Query().Get("type") // "mod" or "plugin"

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	serverDir := h.provider.GetServerDir(uuid)

	var searchDir string
	var pathPrefix string
	switch modType {
	case "plugin", "plugins":
		searchDir = filepath.Join(serverDir, "plugins")
		pathPrefix = "/plugins"
	default:
		searchDir = filepath.Join(serverDir, "mods")
		pathPrefix = "/mods"
	}

	entries, err := os.ReadDir(searchDir)
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]ModFileInfo{})
			return
		}
		h.logger.Error("Failed to read mod directory", "error", err, "path", searchDir)
		http.Error(w, "Failed to read mod directory", http.StatusInternalServerError)
		return
	}

	var mods []ModFileInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Include .jar and .jar.disabled files
		name := entry.Name()
		if !strings.HasSuffix(name, ".jar") && !strings.HasSuffix(name, ".jar.disabled") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		filePath := filepath.Join(searchDir, entry.Name())
		hash, _ := calculateFileHash(filePath)

		mods = append(mods, ModFileInfo{
			Name:     entry.Name(),
			Path:     filepath.Join(pathPrefix, entry.Name()),
			Size:     info.Size(),
			Modified: info.ModTime(),
			Hash:     hash,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mods)
}

// DownloadMod handles POST /api/servers/{uuid}/minecraft/mods/download
func (h *MinecraftHandlers) DownloadMod(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	var req DownloadModRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.URL == "" || req.Filename == "" || req.Destination == "" {
		http.Error(w, "url, filename, and destination are required", http.StatusBadRequest)
		return
	}

	// Validate destination is safe (only /mods or /plugins)
	if req.Destination != "/mods" && req.Destination != "/plugins" {
		http.Error(w, "destination must be /mods or /plugins", http.StatusBadRequest)
		return
	}

	serverDir := h.provider.GetServerDir(uuid)
	destDir := filepath.Join(serverDir, req.Destination)

	// Create destination directory if it doesn't exist
	if err := os.MkdirAll(destDir, 0755); err != nil {
		h.logger.Error("Failed to create mod directory", "error", err, "path", destDir)
		http.Error(w, "Failed to create mod directory", http.StatusInternalServerError)
		return
	}

	destPath := filepath.Join(destDir, req.Filename)

	// Download the file
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(req.URL)
	if err != nil {
		h.logger.Error("Failed to download mod", "error", err, "url", req.URL)
		http.Error(w, fmt.Sprintf("Failed to download: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		h.logger.Error("Download failed", "status", resp.StatusCode, "url", req.URL)
		http.Error(w, fmt.Sprintf("Download failed with status %d", resp.StatusCode), http.StatusBadGateway)
		return
	}

	// Create the file
	file, err := os.Create(destPath)
	if err != nil {
		h.logger.Error("Failed to create file", "error", err, "path", destPath)
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Choose hash algorithm based on request (default to sha512 for Modrinth compatibility)
	var hasher hash.Hash
	switch req.HashAlgorithm {
	case "sha1":
		hasher = sha1.New()
	case "md5":
		hasher = md5.New()
	default:
		hasher = sha512.New()
	}

	// Always calculate SHA512 for storage (used for Modrinth update checks)
	sha512Hasher := sha512.New()
	writer := io.MultiWriter(file, hasher, sha512Hasher)

	size, err := io.Copy(writer, resp.Body)
	if err != nil {
		os.Remove(destPath)
		h.logger.Error("Failed to download file", "error", err)
		http.Error(w, "Failed to download file", http.StatusInternalServerError)
		return
	}

	calculatedHash := hex.EncodeToString(hasher.Sum(nil))
	sha512Hash := hex.EncodeToString(sha512Hasher.Sum(nil))

	// Verify hash if provided
	if req.ExpectedHash != "" {
		if calculatedHash != req.ExpectedHash {
			os.Remove(destPath)
			h.logger.Warn("Hash mismatch", "algorithm", req.HashAlgorithm, "expected", req.ExpectedHash, "got", calculatedHash)
			http.Error(w, "Hash mismatch - file may be corrupted", http.StatusBadRequest)
			return
		}
	}

	h.logger.Info("Downloaded mod", "filename", req.Filename, "size", size, "server", uuid)

	response := DownloadModResponse{
		Path:     filepath.Join(req.Destination, req.Filename),
		Filename: req.Filename,
		Size:     size,
		Hash:     sha512Hash,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// DeleteMod handles DELETE /api/servers/{uuid}/minecraft/mods
func (h *MinecraftHandlers) DeleteMod(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")
	filePath := r.URL.Query().Get("path")

	if filePath == "" {
		http.Error(w, "path query parameter is required", http.StatusBadRequest)
		return
	}

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	serverDir := h.provider.GetServerDir(uuid)

	// Security: ensure path starts with /mods or /plugins
	dir := filepath.Dir(filePath)
	if dir != "/mods" && dir != "/plugins" {
		http.Error(w, "path must be in /mods or /plugins", http.StatusBadRequest)
		return
	}

	fullPath, err := h.provider.ResolvePath(serverDir, filePath)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	if err := os.Remove(fullPath); err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		h.logger.Error("Failed to delete mod", "error", err, "path", fullPath)
		http.Error(w, "Failed to delete mod", http.StatusInternalServerError)
		return
	}

	h.logger.Info("Deleted mod", "path", filePath, "server", uuid)
	w.WriteHeader(http.StatusNoContent)
}

// ToggleMod handles POST /api/servers/{uuid}/minecraft/mods/toggle
func (h *MinecraftHandlers) ToggleMod(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	var req ToggleModRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Path == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}

	serverDir := h.provider.GetServerDir(uuid)

	// Security: ensure path is in /mods or /plugins
	dir := filepath.Dir(req.Path)
	if dir != "/mods" && dir != "/plugins" {
		http.Error(w, "path must be in /mods or /plugins", http.StatusBadRequest)
		return
	}

	fullPath, err := h.provider.ResolvePath(serverDir, req.Path)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	var newPath string
	var disabled bool

	if req.Enable {
		// Enable: rename .jar.disabled to .jar
		if !strings.HasSuffix(req.Path, ".jar.disabled") {
			http.Error(w, "File is not disabled", http.StatusBadRequest)
			return
		}
		newPath = strings.TrimSuffix(req.Path, ".disabled")
		disabled = false
	} else {
		// Disable: rename .jar to .jar.disabled
		if !strings.HasSuffix(req.Path, ".jar") || strings.HasSuffix(req.Path, ".jar.disabled") {
			http.Error(w, "File is already disabled or not a jar file", http.StatusBadRequest)
			return
		}
		newPath = req.Path + ".disabled"
		disabled = true
	}

	newFullPath, err := h.provider.ResolvePath(serverDir, newPath)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	if err := os.Rename(fullPath, newFullPath); err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		h.logger.Error("Failed to toggle mod", "error", err, "from", fullPath, "to", newFullPath)
		http.Error(w, "Failed to toggle mod", http.StatusInternalServerError)
		return
	}

	action := "Disabled"
	if req.Enable {
		action = "Enabled"
	}
	h.logger.Info(action+" mod", "path", newPath, "server", uuid)

	response := ToggleModResponse{
		Path:     newPath,
		Disabled: disabled,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// BackupMod handles POST /api/servers/{uuid}/minecraft/mods/backup
func (h *MinecraftHandlers) BackupMod(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	var req BackupModRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Path == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}

	serverDir := h.provider.GetServerDir(uuid)

	// Security: ensure path is in /mods or /plugins
	dir := filepath.Dir(req.Path)
	if dir != "/mods" && dir != "/plugins" {
		http.Error(w, "path must be in /mods or /plugins", http.StatusBadRequest)
		return
	}

	fullPath, err := h.provider.ResolvePath(serverDir, req.Path)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Create backup directory
	backupDir := filepath.Join(serverDir, dir, ".backups")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		h.logger.Error("Failed to create backup directory", "error", err, "path", backupDir)
		http.Error(w, "Failed to create backup directory", http.StatusInternalServerError)
		return
	}

	// Calculate hash before backup
	hash, err := calculateFileHash(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		h.logger.Error("Failed to calculate hash", "error", err, "path", fullPath)
		http.Error(w, "Failed to calculate file hash", http.StatusInternalServerError)
		return
	}

	// Backup filename: original_name.backup_timestamp.jar
	filename := filepath.Base(req.Path)
	ext := filepath.Ext(filename)
	name := strings.TrimSuffix(filename, ext)
	backupFilename := fmt.Sprintf("%s.backup_%d%s", name, time.Now().Unix(), ext)
	backupPath := filepath.Join(dir, ".backups", backupFilename)
	backupFullPath := filepath.Join(serverDir, backupPath)

	// Copy file to backup location
	if err := copyFile(fullPath, backupFullPath); err != nil {
		h.logger.Error("Failed to backup mod", "error", err, "from", fullPath, "to", backupFullPath)
		http.Error(w, "Failed to backup mod", http.StatusInternalServerError)
		return
	}

	h.logger.Info("Backed up mod", "path", req.Path, "backup", backupPath, "server", uuid)

	response := BackupModResponse{
		BackupPath: backupPath,
		Hash:       hash,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// RestoreMod handles POST /api/servers/{uuid}/minecraft/mods/restore
func (h *MinecraftHandlers) RestoreMod(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	var req RestoreModRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.BackupPath == "" || req.RestorePath == "" {
		http.Error(w, "backup_path and restore_path are required", http.StatusBadRequest)
		return
	}

	serverDir := h.provider.GetServerDir(uuid)

	// Security: validate both paths
	for _, path := range []string{req.BackupPath, req.RestorePath} {
		dir := filepath.Dir(path)
		baseDir := filepath.Dir(dir) // Get parent in case of .backups
		if dir != "/mods" && dir != "/plugins" &&
			baseDir != "/mods" && baseDir != "/plugins" {
			http.Error(w, "paths must be in /mods or /plugins", http.StatusBadRequest)
			return
		}
	}

	backupFullPath, err := h.provider.ResolvePath(serverDir, req.BackupPath)
	if err != nil {
		http.Error(w, "Invalid backup path", http.StatusBadRequest)
		return
	}

	restoreFullPath, err := h.provider.ResolvePath(serverDir, req.RestorePath)
	if err != nil {
		http.Error(w, "Invalid restore path", http.StatusBadRequest)
		return
	}

	// Check backup exists
	backupInfo, err := os.Stat(backupFullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Backup file not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to check backup file", http.StatusInternalServerError)
		return
	}

	// Delete current file if it exists
	if _, err := os.Stat(restoreFullPath); err == nil {
		if err := os.Remove(restoreFullPath); err != nil {
			h.logger.Error("Failed to remove current file for restore", "error", err)
			http.Error(w, "Failed to remove current file", http.StatusInternalServerError)
			return
		}
	}

	// Copy backup to restore location
	if err := copyFile(backupFullPath, restoreFullPath); err != nil {
		h.logger.Error("Failed to restore mod", "error", err, "from", backupFullPath, "to", restoreFullPath)
		http.Error(w, "Failed to restore mod", http.StatusInternalServerError)
		return
	}

	// Calculate hash of restored file
	hash, _ := calculateFileHash(restoreFullPath)

	// Delete the backup file after successful restore
	os.Remove(backupFullPath)

	h.logger.Info("Restored mod", "backup", req.BackupPath, "restored", req.RestorePath, "server", uuid)

	response := RestoreModResponse{
		Path: req.RestorePath,
		Hash: hash,
		Size: backupInfo.Size(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

func calculateFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha512.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
