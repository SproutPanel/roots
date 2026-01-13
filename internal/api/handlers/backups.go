package handlers

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/sproutpanel/roots/internal/config"
)

// BackupManager handles backup-related API requests
type BackupManager struct {
	config    *config.Config
	serverMgr *ServerManager
	logger    *slog.Logger
	backups   map[string]*BackupInfo // backup_id -> BackupInfo
	mu        sync.RWMutex
}

// BackupInfo represents a backup's metadata
type BackupInfo struct {
	ID          string    `json:"id"`
	ServerUUID  string    `json:"server_uuid"`
	Name        string    `json:"name"`
	Status      string    `json:"status"` // pending, in_progress, completed, failed
	Paths       []string  `json:"paths"`
	SizeBytes   int64     `json:"size_bytes,omitempty"`
	Checksum    string    `json:"checksum,omitempty"`
	ErrorMsg    string    `json:"error_message,omitempty"`
	UploadToS3  bool      `json:"upload_to_s3,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

// NewBackupManager creates a new backup manager
func NewBackupManager(cfg *config.Config, serverMgr *ServerManager, logger *slog.Logger) *BackupManager {
	bm := &BackupManager{
		config:    cfg,
		serverMgr: serverMgr,
		logger:    logger,
		backups:   make(map[string]*BackupInfo),
	}

	// Ensure backups directory exists
	if err := os.MkdirAll(cfg.Storage.Backups, 0755); err != nil {
		logger.Error("failed to create backups directory", "error", err)
	}

	// Load existing backup metadata
	bm.loadBackups()

	return bm
}

// loadBackups loads backup metadata from disk
func (bm *BackupManager) loadBackups() {
	entries, err := os.ReadDir(bm.config.Storage.Backups)
	if err != nil {
		if !os.IsNotExist(err) {
			bm.logger.Error("failed to read backups directory", "error", err)
		}
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		serverUUID := entry.Name()
		serverBackupDir := filepath.Join(bm.config.Storage.Backups, serverUUID)

		backupEntries, err := os.ReadDir(serverBackupDir)
		if err != nil {
			continue
		}

		for _, be := range backupEntries {
			if !strings.HasSuffix(be.Name(), ".json") {
				continue
			}

			metaPath := filepath.Join(serverBackupDir, be.Name())
			data, err := os.ReadFile(metaPath)
			if err != nil {
				continue
			}

			var backup BackupInfo
			if err := json.Unmarshal(data, &backup); err != nil {
				bm.logger.Error("failed to parse backup metadata", "path", metaPath, "error", err)
				continue
			}

			bm.backups[backup.ID] = &backup
		}
	}

	bm.logger.Info("loaded backups", "count", len(bm.backups))
}

// saveBackupMeta saves backup metadata to disk
func (bm *BackupManager) saveBackupMeta(backup *BackupInfo) error {
	serverDir := filepath.Join(bm.config.Storage.Backups, backup.ServerUUID)
	if err := os.MkdirAll(serverDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal backup: %w", err)
	}

	metaPath := filepath.Join(serverDir, backup.ID+".json")
	if err := os.WriteFile(metaPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write backup metadata: %w", err)
	}

	return nil
}

// backupFilePath returns the path to a backup's zip file
func (bm *BackupManager) backupFilePath(serverUUID, backupID string) string {
	return filepath.Join(bm.config.Storage.Backups, serverUUID, backupID+".zip")
}

// UpdateConfig updates the manager's configuration
func (bm *BackupManager) UpdateConfig(cfg *config.Config) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.config = cfg
}

// CreateBackupRequest is the request body for creating a backup
type CreateBackupRequest struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Paths      []string `json:"paths"`
	UploadToS3 bool     `json:"upload_to_s3,omitempty"`
}

// Create handles POST /api/servers/{uuid}/backups
func (bm *BackupManager) Create(w http.ResponseWriter, r *http.Request) {
	serverUUID := chi.URLParam(r, "uuid")

	// Verify server exists
	bm.serverMgr.mu.RLock()
	server, ok := bm.serverMgr.servers[serverUUID]
	bm.serverMgr.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	var req CreateBackupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ID == "" || req.Name == "" || len(req.Paths) == 0 {
		http.Error(w, "id, name, and paths are required", http.StatusBadRequest)
		return
	}

	// Check if backup already exists
	bm.mu.Lock()
	if _, exists := bm.backups[req.ID]; exists {
		bm.mu.Unlock()
		http.Error(w, "Backup already exists", http.StatusConflict)
		return
	}

	backup := &BackupInfo{
		ID:         req.ID,
		ServerUUID: serverUUID,
		Name:       req.Name,
		Status:     "in_progress",
		Paths:      req.Paths,
		UploadToS3: req.UploadToS3,
		CreatedAt:  time.Now(),
	}

	bm.backups[req.ID] = backup
	bm.mu.Unlock()

	// Save initial metadata
	if err := bm.saveBackupMeta(backup); err != nil {
		bm.logger.Error("failed to save backup metadata", "error", err)
	}

	// Report in_progress status to panel immediately
	bm.reportBackupStatus(backup)

	// Start backup creation in background
	go bm.createBackup(server, backup)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(backup)
}

// createBackup creates a backup archive asynchronously
func (bm *BackupManager) createBackup(server *Server, backup *BackupInfo) {
	serverDir := filepath.Join(bm.config.Storage.Servers, server.UUID)
	backupPath := bm.backupFilePath(backup.ServerUUID, backup.ID)

	// Ensure backup directory exists
	if err := os.MkdirAll(filepath.Dir(backupPath), 0755); err != nil {
		bm.failBackup(backup, fmt.Sprintf("Failed to create backup directory: %v", err))
		return
	}

	// Create the zip file
	zipFile, err := os.Create(backupPath)
	if err != nil {
		bm.failBackup(backup, fmt.Sprintf("Failed to create backup file: %v", err))
		return
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Hash writer for checksum
	hasher := sha256.New()
	multiWriter := io.MultiWriter(zipFile, hasher)
	_ = multiWriter // We'll update this to actually use it for checksumming

	var totalSize int64
	var skippedPaths []string
	var validPaths int

	for _, path := range backup.Paths {
		// Normalize path
		path = strings.TrimPrefix(path, "/")
		if path == "" {
			path = "."
		}

		fullPath := filepath.Join(serverDir, path)

		// Check if path exists
		info, err := os.Stat(fullPath)
		if err != nil {
			if os.IsNotExist(err) {
				bm.logger.Warn("backup path does not exist, skipping", "path", path)
				skippedPaths = append(skippedPaths, "/"+path)
				continue
			}
			bm.failBackup(backup, fmt.Sprintf("Failed to stat path %s: %v", path, err))
			return
		}

		validPaths++

		if info.IsDir() {
			// Walk directory
			err = filepath.Walk(fullPath, func(filePath string, fileInfo os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return nil // Skip files we can't access
				}

				// Skip the .roots metadata directory
				if strings.Contains(filePath, "/.roots/") || strings.HasSuffix(filePath, "/.roots") {
					if fileInfo.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}

				// Get relative path from server directory
				relPath, err := filepath.Rel(serverDir, filePath)
				if err != nil {
					return nil
				}

				if fileInfo.IsDir() {
					// Add directory entry
					_, err := zipWriter.Create(relPath + "/")
					return err
				}

				// Add file
				header, err := zip.FileInfoHeader(fileInfo)
				if err != nil {
					return err
				}
				header.Name = relPath
				header.Method = zip.Deflate

				writer, err := zipWriter.CreateHeader(header)
				if err != nil {
					return err
				}

				file, err := os.Open(filePath)
				if err != nil {
					return err
				}
				defer file.Close()

				written, err := io.Copy(writer, file)
				if err != nil {
					return err
				}
				totalSize += written

				return nil
			})

			if err != nil {
				bm.failBackup(backup, fmt.Sprintf("Failed to archive directory %s: %v", path, err))
				return
			}
		} else {
			// Single file
			relPath, _ := filepath.Rel(serverDir, fullPath)

			header, err := zip.FileInfoHeader(info)
			if err != nil {
				bm.failBackup(backup, fmt.Sprintf("Failed to create file header: %v", err))
				return
			}
			header.Name = relPath
			header.Method = zip.Deflate

			writer, err := zipWriter.CreateHeader(header)
			if err != nil {
				bm.failBackup(backup, fmt.Sprintf("Failed to write file to archive: %v", err))
				return
			}

			file, err := os.Open(fullPath)
			if err != nil {
				bm.failBackup(backup, fmt.Sprintf("Failed to open file: %v", err))
				return
			}

			written, err := io.Copy(writer, file)
			file.Close()
			if err != nil {
				bm.failBackup(backup, fmt.Sprintf("Failed to copy file to archive: %v", err))
				return
			}
			totalSize += written
		}
	}

	// Check if any paths were actually backed up
	if validPaths == 0 {
		// Clean up the empty zip file
		zipWriter.Close()
		zipFile.Close()
		os.Remove(backupPath)

		errMsg := "No valid paths to backup"
		if len(skippedPaths) > 0 {
			errMsg = fmt.Sprintf("All requested paths do not exist: %s", strings.Join(skippedPaths, ", "))
		}
		bm.failBackup(backup, errMsg)
		return
	}

	// Close zip writer to flush
	if err := zipWriter.Close(); err != nil {
		bm.failBackup(backup, fmt.Sprintf("Failed to finalize archive: %v", err))
		return
	}

	// Get final file size
	fileInfo, err := zipFile.Stat()
	if err != nil {
		bm.failBackup(backup, fmt.Sprintf("Failed to stat backup file: %v", err))
		return
	}

	// Calculate checksum
	zipFile.Seek(0, 0)
	hasher.Reset()
	io.Copy(hasher, zipFile)
	checksum := hex.EncodeToString(hasher.Sum(nil))

	// Update backup metadata
	bm.mu.Lock()
	backup.Status = "completed"
	backup.SizeBytes = fileInfo.Size()
	backup.Checksum = "sha256:" + checksum
	backup.CompletedAt = time.Now()
	bm.mu.Unlock()

	if err := bm.saveBackupMeta(backup); err != nil {
		bm.logger.Error("failed to save backup metadata", "error", err)
	}

	// Log completion with skipped paths info
	if len(skippedPaths) > 0 {
		bm.logger.Info("backup completed with skipped paths",
			"id", backup.ID,
			"server", backup.ServerUUID,
			"size", backup.SizeBytes,
			"skipped", skippedPaths,
		)
	} else {
		bm.logger.Info("backup completed",
			"id", backup.ID,
			"server", backup.ServerUUID,
			"size", backup.SizeBytes,
		)
	}

	// Report to panel
	bm.reportBackupStatus(backup)
}

// failBackup marks a backup as failed
func (bm *BackupManager) failBackup(backup *BackupInfo, errMsg string) {
	bm.mu.Lock()
	backup.Status = "failed"
	backup.ErrorMsg = errMsg
	bm.mu.Unlock()

	bm.saveBackupMeta(backup)
	bm.logger.Error("backup failed", "id", backup.ID, "error", errMsg)

	bm.reportBackupStatus(backup)
}

// reportBackupStatus sends backup status to the panel
func (bm *BackupManager) reportBackupStatus(backup *BackupInfo) {
	if bm.config.Panel.URL == "" || bm.config.Panel.Token == "" {
		return
	}

	url := fmt.Sprintf("%s/api/internal/servers/%s/backups/%s/status",
		bm.config.Panel.URL, backup.ServerUUID, backup.ID)

	payload := map[string]interface{}{
		"status":        backup.Status,
		"size_bytes":    backup.SizeBytes,
		"checksum":      backup.Checksum,
		"error_message": backup.ErrorMsg,
		"name":          backup.Name,
		"paths":         backup.Paths,
		"upload_to_s3":  backup.UploadToS3,
	}

	// Include local path for completed backups
	if backup.Status == "completed" {
		payload["local_path"] = bm.backupFilePath(backup.ServerUUID, backup.ID)
	}

	data, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		bm.logger.Error("failed to create panel callback request", "error", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+bm.config.Panel.Token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		bm.logger.Error("failed to send backup callback", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bm.logger.Error("backup callback failed", "status", resp.StatusCode, "backup", backup.ID)
	}
}

// reportBackupDeleted notifies the panel that a backup was deleted
func (bm *BackupManager) reportBackupDeleted(serverUUID, backupID string) {
	if bm.config.Panel.URL == "" || bm.config.Panel.Token == "" {
		return
	}

	url := fmt.Sprintf("%s/api/internal/servers/%s/backups/%s/deleted",
		bm.config.Panel.URL, serverUUID, backupID)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		bm.logger.Error("failed to create panel delete callback request", "error", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+bm.config.Panel.Token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		bm.logger.Error("failed to send backup delete callback", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bm.logger.Error("backup delete callback failed", "status", resp.StatusCode, "backup", backupID)
	}
}

// reportBackupRestored notifies the panel that a backup was restored
func (bm *BackupManager) reportBackupRestored(serverUUID, backupID string) {
	if bm.config.Panel.URL == "" || bm.config.Panel.Token == "" {
		return
	}

	url := fmt.Sprintf("%s/api/internal/servers/%s/backups/%s/restored",
		bm.config.Panel.URL, serverUUID, backupID)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		bm.logger.Error("failed to create panel restore callback request", "error", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+bm.config.Panel.Token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		bm.logger.Error("failed to send backup restore callback", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bm.logger.Error("backup restore callback failed", "status", resp.StatusCode, "backup", backupID)
	}
}

// List handles GET /api/servers/{uuid}/backups
func (bm *BackupManager) List(w http.ResponseWriter, r *http.Request) {
	serverUUID := chi.URLParam(r, "uuid")

	// Verify server exists
	bm.serverMgr.mu.RLock()
	_, ok := bm.serverMgr.servers[serverUUID]
	bm.serverMgr.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	bm.mu.RLock()
	backups := make([]*BackupInfo, 0)
	for _, b := range bm.backups {
		if b.ServerUUID == serverUUID {
			backups = append(backups, b)
		}
	}
	bm.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(backups)
}

// Get handles GET /api/servers/{uuid}/backups/{backup_id}
func (bm *BackupManager) Get(w http.ResponseWriter, r *http.Request) {
	serverUUID := chi.URLParam(r, "uuid")
	backupID := chi.URLParam(r, "backup_id")

	bm.mu.RLock()
	backup, ok := bm.backups[backupID]
	bm.mu.RUnlock()

	if !ok || backup.ServerUUID != serverUUID {
		http.Error(w, "Backup not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(backup)
}

// Download handles GET /api/servers/{uuid}/backups/{backup_id}/download
func (bm *BackupManager) Download(w http.ResponseWriter, r *http.Request) {
	serverUUID := chi.URLParam(r, "uuid")
	backupID := chi.URLParam(r, "backup_id")

	bm.mu.RLock()
	backup, ok := bm.backups[backupID]
	bm.mu.RUnlock()

	if !ok || backup.ServerUUID != serverUUID {
		http.Error(w, "Backup not found", http.StatusNotFound)
		return
	}

	if backup.Status != "completed" {
		http.Error(w, "Backup not ready for download", http.StatusBadRequest)
		return
	}

	backupPath := bm.backupFilePath(serverUUID, backupID)

	file, err := os.Open(backupPath)
	if err != nil {
		bm.logger.Error("failed to open backup file", "error", err)
		http.Error(w, "Backup file not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		http.Error(w, "Failed to read backup", http.StatusInternalServerError)
		return
	}

	// Set headers for download
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.zip"`, backupID))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))

	// Stream the file
	io.Copy(w, file)
}

// Delete handles DELETE /api/servers/{uuid}/backups/{backup_id}
func (bm *BackupManager) Delete(w http.ResponseWriter, r *http.Request) {
	serverUUID := chi.URLParam(r, "uuid")
	backupID := chi.URLParam(r, "backup_id")

	bm.mu.Lock()
	backup, ok := bm.backups[backupID]
	if !ok || backup.ServerUUID != serverUUID {
		bm.mu.Unlock()
		http.Error(w, "Backup not found", http.StatusNotFound)
		return
	}

	delete(bm.backups, backupID)
	bm.mu.Unlock()

	// Delete files
	backupPath := bm.backupFilePath(serverUUID, backupID)
	metaPath := filepath.Join(bm.config.Storage.Backups, serverUUID, backupID+".json")

	os.Remove(backupPath)
	os.Remove(metaPath)

	bm.logger.Info("backup deleted", "id", backupID, "server", serverUUID)

	// Notify panel
	bm.reportBackupDeleted(serverUUID, backupID)

	w.WriteHeader(http.StatusNoContent)
}

// RestoreRequest is the request body for restoring a backup
type RestoreRequest struct {
	Paths []string `json:"paths,omitempty"` // Optional: restore only specific paths
}

// Restore handles POST /api/servers/{uuid}/backups/{backup_id}/restore
func (bm *BackupManager) Restore(w http.ResponseWriter, r *http.Request) {
	serverUUID := chi.URLParam(r, "uuid")
	backupID := chi.URLParam(r, "backup_id")

	// Verify server exists and is offline
	bm.serverMgr.mu.RLock()
	server, ok := bm.serverMgr.servers[serverUUID]
	bm.serverMgr.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	if server.Status == "online" || server.Status == "starting" {
		http.Error(w, "Server must be stopped before restoring", http.StatusBadRequest)
		return
	}

	bm.mu.RLock()
	backup, ok := bm.backups[backupID]
	bm.mu.RUnlock()

	if !ok || backup.ServerUUID != serverUUID {
		http.Error(w, "Backup not found", http.StatusNotFound)
		return
	}

	if backup.Status != "completed" {
		http.Error(w, "Backup not ready for restore", http.StatusBadRequest)
		return
	}

	var req RestoreRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
	}

	// Perform restore
	if err := bm.restoreBackup(server, backup, req.Paths); err != nil {
		bm.logger.Error("restore failed", "error", err)
		http.Error(w, fmt.Sprintf("Restore failed: %v", err), http.StatusInternalServerError)
		return
	}

	bm.logger.Info("backup restored", "id", backupID, "server", serverUUID)

	// Notify panel
	bm.reportBackupRestored(serverUUID, backupID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "restored"})
}

// restoreBackup extracts backup contents to the server directory
func (bm *BackupManager) restoreBackup(server *Server, backup *BackupInfo, filterPaths []string) error {
	backupPath := bm.backupFilePath(backup.ServerUUID, backup.ID)
	serverDir := filepath.Join(bm.config.Storage.Servers, server.UUID)

	zipReader, err := zip.OpenReader(backupPath)
	if err != nil {
		return fmt.Errorf("failed to open backup: %w", err)
	}
	defer zipReader.Close()

	// Build filter set if specified
	var pathFilter map[string]bool
	if len(filterPaths) > 0 {
		pathFilter = make(map[string]bool)
		for _, p := range filterPaths {
			pathFilter[strings.TrimPrefix(p, "/")] = true
		}
	}

	for _, file := range zipReader.File {
		// Skip if filtering and path doesn't match
		if pathFilter != nil {
			matched := false
			for filterPath := range pathFilter {
				if strings.HasPrefix(file.Name, filterPath) || filterPath == "." {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		destPath := filepath.Join(serverDir, file.Name)

		// Security: prevent path traversal
		if !strings.HasPrefix(destPath, serverDir) {
			continue
		}

		if file.FileInfo().IsDir() {
			os.MkdirAll(destPath, file.Mode())
			continue
		}

		// Create parent directories
		os.MkdirAll(filepath.Dir(destPath), 0755)

		// Extract file
		srcFile, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to read file from archive: %w", err)
		}

		destFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, file.Mode())
		if err != nil {
			srcFile.Close()
			return fmt.Errorf("failed to create file: %w", err)
		}

		_, err = io.Copy(destFile, srcFile)
		srcFile.Close()
		destFile.Close()

		if err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
	}

	return nil
}

// DeleteServerBackups removes all backups for a server (called when server is deleted)
func (bm *BackupManager) DeleteServerBackups(ctx context.Context, serverUUID string) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	// Remove from memory
	for id, backup := range bm.backups {
		if backup.ServerUUID == serverUUID {
			delete(bm.backups, id)
		}
	}

	// Remove from disk
	serverBackupDir := filepath.Join(bm.config.Storage.Backups, serverUUID)
	return os.RemoveAll(serverBackupDir)
}
