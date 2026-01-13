package handlers

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// FileInfo represents a file or directory
type FileInfo struct {
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	Mode      string    `json:"mode"`
	IsDir     bool      `json:"is_dir"`
	Modified  time.Time `json:"modified"`
	MimeType  string    `json:"mime_type,omitempty"`
}

// ListFilesResponse is the response for listing files
type ListFilesResponse struct {
	Path  string      `json:"path"`
	Files []*FileInfo `json:"files"`
}

// ListFiles handles GET /api/servers/{uuid}/files
func (sm *ServerManager) ListFiles(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")
	requestedPath := r.URL.Query().Get("path")
	if requestedPath == "" {
		requestedPath = "/"
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	// Validate server exists
	sm.mu.RLock()
	_, ok := sm.servers[uuid]
	sm.mu.RUnlock()
	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Resolve and validate path
	fullPath, err := sm.resolvePath(serverDir, requestedPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if path exists
	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Path not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to access path", http.StatusInternalServerError)
		}
		return
	}

	if !info.IsDir() {
		http.Error(w, "Path is not a directory", http.StatusBadRequest)
		return
	}

	// List directory contents
	entries, err := os.ReadDir(fullPath)
	if err != nil {
		http.Error(w, "Failed to read directory", http.StatusInternalServerError)
		return
	}

	// Check if we should show hidden/debug files
	showHidden := r.URL.Query().Get("show_hidden") == "true"

	files := make([]*FileInfo, 0, len(entries))
	for _, entry := range entries {
		// Skip .roots directory unless show_hidden is true
		if entry.Name() == ".roots" && !showHidden {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		relativePath := filepath.Join(requestedPath, entry.Name())
		fileInfo := &FileInfo{
			Name:     entry.Name(),
			Path:     relativePath,
			Size:     info.Size(),
			Mode:     info.Mode().String(),
			IsDir:    entry.IsDir(),
			Modified: info.ModTime(),
		}

		if !entry.IsDir() {
			fileInfo.MimeType = getMimeType(entry.Name())
		}

		files = append(files, fileInfo)
	}

	// Sort: .roots first (if showing), then directories, then by name
	sort.Slice(files, func(i, j int) bool {
		// .roots always comes first when visible
		if files[i].Name == ".roots" {
			return true
		}
		if files[j].Name == ".roots" {
			return false
		}
		// Directories before files
		if files[i].IsDir != files[j].IsDir {
			return files[i].IsDir
		}
		// Alphabetical by name
		return strings.ToLower(files[i].Name) < strings.ToLower(files[j].Name)
	})

	response := &ListFilesResponse{
		Path:  requestedPath,
		Files: files,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// ReadFile handles GET /api/servers/{uuid}/files/content
func (sm *ServerManager) ReadFile(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")
	requestedPath := r.URL.Query().Get("path")
	if requestedPath == "" {
		http.Error(w, "path parameter is required", http.StatusBadRequest)
		return
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	// Validate server exists
	sm.mu.RLock()
	_, ok := sm.servers[uuid]
	sm.mu.RUnlock()
	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Resolve and validate path
	fullPath, err := sm.resolvePath(serverDir, requestedPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if path exists
	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "File not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to access file", http.StatusInternalServerError)
		}
		return
	}

	if info.IsDir() {
		http.Error(w, "Path is a directory", http.StatusBadRequest)
		return
	}

	// Check file size (limit to 5MB for reading)
	if info.Size() > 5*1024*1024 {
		http.Error(w, "File too large (max 5MB)", http.StatusBadRequest)
		return
	}

	// Read file
	content, err := os.ReadFile(fullPath)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	// Return as JSON with metadata
	response := struct {
		Path     string `json:"path"`
		Name     string `json:"name"`
		Content  string `json:"content"`
		Size     int64  `json:"size"`
		MimeType string `json:"mime_type"`
	}{
		Path:     requestedPath,
		Name:     info.Name(),
		Content:  string(content),
		Size:     info.Size(),
		MimeType: getMimeType(info.Name()),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// DownloadFile handles GET /api/servers/{uuid}/files/download
func (sm *ServerManager) DownloadFile(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")
	requestedPath := r.URL.Query().Get("path")
	if requestedPath == "" {
		http.Error(w, "path parameter is required", http.StatusBadRequest)
		return
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	// Validate server exists
	sm.mu.RLock()
	_, ok := sm.servers[uuid]
	sm.mu.RUnlock()
	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Resolve and validate path
	fullPath, err := sm.resolvePath(serverDir, requestedPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if path exists
	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "File not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to access file", http.StatusInternalServerError)
		}
		return
	}

	if info.IsDir() {
		http.Error(w, "Path is a directory", http.StatusBadRequest)
		return
	}

	// Open file for streaming
	file, err := os.Open(fullPath)
	if err != nil {
		http.Error(w, "Failed to open file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Set headers for download
	filename := filepath.Base(fullPath)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))

	// Stream file to response
	io.Copy(w, file)
}

// WriteFileRequest is the request body for writing a file
type WriteFileRequest struct {
	Content string `json:"content"`
}

// WriteFile handles PUT /api/servers/{uuid}/files/content
func (sm *ServerManager) WriteFile(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")
	requestedPath := r.URL.Query().Get("path")
	if requestedPath == "" {
		http.Error(w, "path parameter is required", http.StatusBadRequest)
		return
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	// Validate server exists
	sm.mu.RLock()
	_, ok := sm.servers[uuid]
	sm.mu.RUnlock()
	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Resolve and validate path
	fullPath, err := sm.resolvePath(serverDir, requestedPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Read raw body first (before attempting JSON decode)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Try to parse as JSON, fall back to raw content
	var req WriteFileRequest
	if err := json.Unmarshal(body, &req); err != nil {
		// Not JSON - use raw body as content (for binary uploads)
		req.Content = string(body)
	}

	// Ensure parent directory exists
	parentDir := filepath.Dir(fullPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		http.Error(w, "Failed to create parent directory", http.StatusInternalServerError)
		return
	}

	// Write file
	if err := os.WriteFile(fullPath, []byte(req.Content), 0644); err != nil {
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// CreateFileRequest is the request body for creating a file or directory
type CreateFileRequest struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
}

// CreateFile handles POST /api/servers/{uuid}/files
func (sm *ServerManager) CreateFile(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")
	requestedPath := r.URL.Query().Get("path")
	if requestedPath == "" {
		requestedPath = "/"
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	// Validate server exists
	sm.mu.RLock()
	_, ok := sm.servers[uuid]
	sm.mu.RUnlock()
	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Parse request
	var req CreateFileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	// Validate name
	if strings.Contains(req.Name, "/") || strings.Contains(req.Name, "\\") {
		http.Error(w, "Invalid file name", http.StatusBadRequest)
		return
	}

	// Resolve parent path
	parentPath, err := sm.resolvePath(serverDir, requestedPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fullPath := filepath.Join(parentPath, req.Name)

	// Check if already exists
	if _, err := os.Stat(fullPath); err == nil {
		http.Error(w, "File or directory already exists", http.StatusConflict)
		return
	}

	if req.IsDir {
		if err := os.MkdirAll(fullPath, 0755); err != nil {
			http.Error(w, "Failed to create directory", http.StatusInternalServerError)
			return
		}
	} else {
		// Create empty file
		file, err := os.Create(fullPath)
		if err != nil {
			http.Error(w, "Failed to create file", http.StatusInternalServerError)
			return
		}
		file.Close()
	}

	w.WriteHeader(http.StatusCreated)
}

// DeleteFile handles DELETE /api/servers/{uuid}/files
func (sm *ServerManager) DeleteFile(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")
	requestedPath := r.URL.Query().Get("path")
	if requestedPath == "" {
		http.Error(w, "path parameter is required", http.StatusBadRequest)
		return
	}

	// Prevent deleting root
	if requestedPath == "/" || requestedPath == "" {
		http.Error(w, "Cannot delete root directory", http.StatusBadRequest)
		return
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	// Validate server exists
	sm.mu.RLock()
	_, ok := sm.servers[uuid]
	sm.mu.RUnlock()
	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Resolve and validate path
	fullPath, err := sm.resolvePath(serverDir, requestedPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if path exists
	if _, err := os.Stat(fullPath); err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Path not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to access path", http.StatusInternalServerError)
		}
		return
	}

	// Delete
	if err := os.RemoveAll(fullPath); err != nil {
		http.Error(w, "Failed to delete", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RenameFileRequest is the request body for renaming a file
type RenameFileRequest struct {
	NewPath string `json:"new_path"`
}

// RenameFile handles POST /api/servers/{uuid}/files/rename
func (sm *ServerManager) RenameFile(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")
	requestedPath := r.URL.Query().Get("path")
	if requestedPath == "" {
		http.Error(w, "path parameter is required", http.StatusBadRequest)
		return
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	// Validate server exists
	sm.mu.RLock()
	_, ok := sm.servers[uuid]
	sm.mu.RUnlock()
	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Parse request
	var req RenameFileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.NewPath == "" {
		http.Error(w, "new_path is required", http.StatusBadRequest)
		return
	}

	// Resolve paths
	oldPath, err := sm.resolvePath(serverDir, requestedPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newPath, err := sm.resolvePath(serverDir, req.NewPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check source exists
	if _, err := os.Stat(oldPath); err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Source path not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to access source path", http.StatusInternalServerError)
		}
		return
	}

	// Check destination doesn't exist
	if _, err := os.Stat(newPath); err == nil {
		http.Error(w, "Destination already exists", http.StatusConflict)
		return
	}

	// Ensure parent directory exists
	parentDir := filepath.Dir(newPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		http.Error(w, "Failed to create parent directory", http.StatusInternalServerError)
		return
	}

	// Rename
	if err := os.Rename(oldPath, newPath); err != nil {
		http.Error(w, "Failed to rename", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// CompressRequest is the request body for compressing files
type CompressRequest struct {
	Paths       []string `json:"paths"`
	Destination string   `json:"destination"`
}

// CompressFiles handles POST /api/servers/{uuid}/files/compress
func (sm *ServerManager) CompressFiles(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")
	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	// Validate server directory exists
	if _, err := os.Stat(serverDir); os.IsNotExist(err) {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Parse request
	var req CompressRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.Paths) == 0 {
		http.Error(w, "paths is required", http.StatusBadRequest)
		return
	}

	if req.Destination == "" {
		http.Error(w, "destination is required", http.StatusBadRequest)
		return
	}

	// Resolve destination path
	destPath, err := sm.resolvePath(serverDir, req.Destination)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if destination already exists
	if _, err := os.Stat(destPath); err == nil {
		http.Error(w, "Destination file already exists", http.StatusConflict)
		return
	}

	// Create the zip file
	zipFile, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "Failed to create archive", http.StatusInternalServerError)
		return
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Add each path to the archive
	for _, path := range req.Paths {
		fullPath, err := sm.resolvePath(serverDir, path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		info, err := os.Stat(fullPath)
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, fmt.Sprintf("Path not found: %s", path), http.StatusNotFound)
			} else {
				http.Error(w, "Failed to access path", http.StatusInternalServerError)
			}
			return
		}

		baseName := filepath.Base(fullPath)

		if info.IsDir() {
			// Walk the directory
			err = filepath.Walk(fullPath, func(filePath string, fileInfo os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}

				// Calculate relative path within the zip
				relPath, err := filepath.Rel(fullPath, filePath)
				if err != nil {
					return err
				}

				// Combine with the base directory name
				zipPath := filepath.Join(baseName, relPath)
				if relPath == "." {
					zipPath = baseName
				}

				// Skip directories - they're created implicitly
				if fileInfo.IsDir() {
					return nil
				}

				// Create the file in the zip
				header, err := zip.FileInfoHeader(fileInfo)
				if err != nil {
					return err
				}
				header.Name = zipPath
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

				_, err = io.Copy(writer, file)
				return err
			})

			if err != nil {
				http.Error(w, "Failed to add directory to archive", http.StatusInternalServerError)
				return
			}
		} else {
			// Single file
			header, err := zip.FileInfoHeader(info)
			if err != nil {
				http.Error(w, "Failed to create file header", http.StatusInternalServerError)
				return
			}
			header.Name = baseName
			header.Method = zip.Deflate

			writer, err := zipWriter.CreateHeader(header)
			if err != nil {
				http.Error(w, "Failed to add file to archive", http.StatusInternalServerError)
				return
			}

			file, err := os.Open(fullPath)
			if err != nil {
				http.Error(w, "Failed to open file", http.StatusInternalServerError)
				return
			}
			defer file.Close()

			if _, err := io.Copy(writer, file); err != nil {
				http.Error(w, "Failed to write file to archive", http.StatusInternalServerError)
				return
			}
		}
	}

	w.WriteHeader(http.StatusCreated)
}

// DecompressRequest is the request body for decompressing an archive
type DecompressRequest struct {
	Path        string `json:"path"`
	Destination string `json:"destination"`
}

// DecompressFile handles POST /api/servers/{uuid}/files/decompress
func (sm *ServerManager) DecompressFile(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")
	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	// Validate server directory exists
	if _, err := os.Stat(serverDir); os.IsNotExist(err) {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Parse request
	var req DecompressRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Path == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}

	if req.Destination == "" {
		req.Destination = filepath.Dir(req.Path)
	}

	// Resolve paths
	archivePath, err := sm.resolvePath(serverDir, req.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	destPath, err := sm.resolvePath(serverDir, req.Destination)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if archive exists
	if _, err := os.Stat(archivePath); err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Archive not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to access archive", http.StatusInternalServerError)
		}
		return
	}

	// Open the zip file
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		http.Error(w, "Failed to open archive", http.StatusInternalServerError)
		return
	}
	defer reader.Close()

	// Ensure destination directory exists
	if err := os.MkdirAll(destPath, 0755); err != nil {
		http.Error(w, "Failed to create destination directory", http.StatusInternalServerError)
		return
	}

	// Extract each file
	for _, file := range reader.File {
		// Construct the full path
		filePath := filepath.Join(destPath, file.Name)

		// Validate path doesn't escape destination
		absDestPath, _ := filepath.Abs(destPath)
		absFilePath, _ := filepath.Abs(filePath)
		if !strings.HasPrefix(absFilePath, absDestPath) {
			http.Error(w, "Invalid file path in archive", http.StatusBadRequest)
			return
		}

		if file.FileInfo().IsDir() {
			// Create directory
			if err := os.MkdirAll(filePath, file.Mode()); err != nil {
				http.Error(w, "Failed to create directory", http.StatusInternalServerError)
				return
			}
			continue
		}

		// Create parent directory
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			http.Error(w, "Failed to create parent directory", http.StatusInternalServerError)
			return
		}

		// Create the file
		outFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			http.Error(w, "Failed to create file", http.StatusInternalServerError)
			return
		}

		rc, err := file.Open()
		if err != nil {
			outFile.Close()
			http.Error(w, "Failed to read archive entry", http.StatusInternalServerError)
			return
		}

		_, err = io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()

		if err != nil {
			http.Error(w, "Failed to extract file", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

// MoveFileRequest is the request body for moving a file
type MoveFileRequest struct {
	Destination string `json:"destination"`
}

// MoveFile handles POST /api/servers/{uuid}/files/move
func (sm *ServerManager) MoveFile(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")
	requestedPath := r.URL.Query().Get("path")
	if requestedPath == "" {
		http.Error(w, "path parameter is required", http.StatusBadRequest)
		return
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	// Validate server exists
	sm.mu.RLock()
	_, ok := sm.servers[uuid]
	sm.mu.RUnlock()
	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Parse request
	var req MoveFileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Destination == "" {
		http.Error(w, "destination is required", http.StatusBadRequest)
		return
	}

	// Resolve paths
	oldPath, err := sm.resolvePath(serverDir, requestedPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newPath, err := sm.resolvePath(serverDir, req.Destination)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check source exists
	sourceInfo, err := os.Stat(oldPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Source path not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to access source path", http.StatusInternalServerError)
		}
		return
	}

	// Determine if destination should be treated as a directory
	destIsDir := false
	destInfo, err := os.Stat(newPath)
	if err == nil {
		// Destination exists - check if it's a directory
		destIsDir = destInfo.IsDir()
	} else if os.IsNotExist(err) {
		// Destination doesn't exist - treat as directory if:
		// 1. Path ends with /
		// 2. Source is a file and destination has no extension (likely a directory path)
		if strings.HasSuffix(req.Destination, "/") {
			destIsDir = true
		} else if !sourceInfo.IsDir() && filepath.Ext(newPath) == "" && filepath.Ext(oldPath) != "" {
			// Source is a file with extension, dest has no extension - likely meant as directory
			destIsDir = true
		}
	}

	if destIsDir {
		// Create the directory if it doesn't exist
		if err := os.MkdirAll(newPath, 0755); err != nil {
			http.Error(w, "Failed to create destination directory", http.StatusInternalServerError)
			return
		}
		// Move into the directory, keeping the original name
		newPath = filepath.Join(newPath, filepath.Base(oldPath))
	}

	// Check destination doesn't already exist
	if _, err := os.Stat(newPath); err == nil {
		http.Error(w, "Destination already exists", http.StatusConflict)
		return
	}

	// Prevent moving a directory into itself
	if sourceInfo.IsDir() {
		absOldPath, _ := filepath.Abs(oldPath)
		absNewPath, _ := filepath.Abs(newPath)
		if strings.HasPrefix(absNewPath, absOldPath+string(filepath.Separator)) {
			http.Error(w, "Cannot move directory into itself", http.StatusBadRequest)
			return
		}
	}

	// Ensure parent directory exists
	parentDir := filepath.Dir(newPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		http.Error(w, "Failed to create parent directory", http.StatusInternalServerError)
		return
	}

	// Move
	if err := os.Rename(oldPath, newPath); err != nil {
		http.Error(w, "Failed to move", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ChmodFileRequest is the request body for changing file permissions
type ChmodFileRequest struct {
	Mode string `json:"mode"`
}

// ChmodFile handles POST /api/servers/{uuid}/files/chmod
func (sm *ServerManager) ChmodFile(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")
	requestedPath := r.URL.Query().Get("path")
	if requestedPath == "" {
		http.Error(w, "path parameter is required", http.StatusBadRequest)
		return
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	// Validate server exists
	sm.mu.RLock()
	_, ok := sm.servers[uuid]
	sm.mu.RUnlock()
	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Parse request
	var req ChmodFileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Mode == "" {
		http.Error(w, "mode is required", http.StatusBadRequest)
		return
	}

	// Parse mode as octal (e.g., "755", "644")
	var mode uint64
	_, err := fmt.Sscanf(req.Mode, "%o", &mode)
	if err != nil || mode > 0777 {
		http.Error(w, "Invalid mode format (use octal, e.g., 755)", http.StatusBadRequest)
		return
	}

	// Resolve path
	fullPath, err := sm.resolvePath(serverDir, requestedPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check path exists
	if _, err := os.Stat(fullPath); err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Path not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to access path", http.StatusInternalServerError)
		}
		return
	}

	// Change permissions
	if err := os.Chmod(fullPath, os.FileMode(mode)); err != nil {
		http.Error(w, "Failed to change permissions", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// resolvePath safely resolves a path within the server directory
func (sm *ServerManager) resolvePath(serverDir, requestedPath string) (string, error) {
	// Clean the path
	cleanPath := filepath.Clean(requestedPath)

	// Join with server directory
	fullPath := filepath.Join(serverDir, cleanPath)

	// Ensure the resolved path is within the server directory
	absServerDir, _ := filepath.Abs(serverDir)
	absFullPath, _ := filepath.Abs(fullPath)

	if !strings.HasPrefix(absFullPath, absServerDir) {
		return "", fmt.Errorf("path traversal detected")
	}

	return fullPath, nil
}

// SearchRequest is the request body for searching files
type SearchRequest struct {
	Directory string `json:"directory"`
	Pattern   string `json:"pattern"`
}

// SearchResult represents a single search result
type SearchResult struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	Size     int64     `json:"size"`
	Mode     string    `json:"mode"`
	IsDir    bool      `json:"is_dir"`
	Modified time.Time `json:"modified"`
	MimeType string    `json:"mime_type,omitempty"`
}

// searchBlacklist contains directories to skip during recursive search
var searchBlacklist = []string{"node_modules", ".wine", ".git", "appcache", "depotcache", "vendor", ".roots"}

// maxSearchDepth is the maximum recursion depth for file search
const maxSearchDepth = 10

// isBlacklisted checks if a directory name is in the blacklist
func isBlacklisted(dirName string) bool {
	lowerName := strings.ToLower(dirName)
	for _, blacklisted := range searchBlacklist {
		if lowerName == strings.ToLower(blacklisted) {
			return true
		}
	}
	return false
}

// SearchFiles handles GET /api/servers/{uuid}/files/search
func (sm *ServerManager) SearchFiles(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")
	directory := r.URL.Query().Get("directory")
	pattern := r.URL.Query().Get("pattern")

	if directory == "" {
		directory = "/"
	}

	if pattern == "" {
		http.Error(w, "pattern parameter is required", http.StatusBadRequest)
		return
	}

	// Require minimum pattern length
	if len(pattern) < 3 {
		http.Error(w, "pattern must be at least 3 characters long", http.StatusBadRequest)
		return
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	// Validate server exists
	sm.mu.RLock()
	_, ok := sm.servers[uuid]
	sm.mu.RUnlock()
	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Resolve and validate directory path
	searchDir, err := sm.resolvePath(serverDir, directory)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if directory exists
	info, err := os.Stat(searchDir)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Directory not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to access directory", http.StatusInternalServerError)
		}
		return
	}

	if !info.IsDir() {
		http.Error(w, "Path is not a directory", http.StatusBadRequest)
		return
	}

	// Convert pattern to lowercase for case-insensitive matching
	patternLower := strings.ToLower(pattern)

	// Perform the search
	var results []SearchResult
	sm.searchDirectory(searchDir, serverDir, patternLower, 0, &results)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// searchDirectory recursively searches for files matching the pattern
func (sm *ServerManager) searchDirectory(dir, serverDir, pattern string, depth int, results *[]SearchResult) {
	if depth > maxSearchDepth {
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		nameLower := strings.ToLower(name)
		fullPath := filepath.Join(dir, name)

		// Calculate relative path from server root
		relativePath, _ := filepath.Rel(serverDir, fullPath)
		relativePath = "/" + relativePath

		// Check if this entry matches the pattern
		matched := false

		// Wildcard or exact matching logic
		if strings.ContainsAny(pattern, "*?") {
			if match, _ := filepath.Match(pattern, nameLower); match {
				matched = true
			}
		} else {
			// Check for substring matches (case-insensitive)
			if strings.Contains(nameLower, pattern) {
				matched = true
			} else {
				// Extension matching logic
				ext := filepath.Ext(nameLower)
				if strings.HasPrefix(pattern, ".") || !strings.Contains(pattern, ".") {
					if strings.TrimPrefix(ext, ".") == strings.TrimPrefix(pattern, ".") {
						matched = true
					}
				}
			}
		}

		if matched {
			info, err := entry.Info()
			if err != nil {
				continue
			}

			result := SearchResult{
				Name:     name,
				Path:     relativePath,
				Size:     info.Size(),
				Mode:     info.Mode().String(),
				IsDir:    entry.IsDir(),
				Modified: info.ModTime(),
			}

			if !entry.IsDir() {
				result.MimeType = getMimeType(name)
			}

			*results = append(*results, result)
		}

		// Recurse into directories (unless blacklisted)
		if entry.IsDir() && !isBlacklisted(name) {
			sm.searchDirectory(fullPath, serverDir, pattern, depth+1, results)
		}
	}
}

// CopyFileRequest is the request body for copying a file
type CopyFileRequest struct {
	Destination string `json:"destination"`
}

// CopyFile handles POST /api/servers/{uuid}/files/copy
func (sm *ServerManager) CopyFile(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")
	requestedPath := r.URL.Query().Get("path")
	if requestedPath == "" {
		http.Error(w, "path parameter is required", http.StatusBadRequest)
		return
	}

	serverDir := filepath.Join(sm.config.Storage.Servers, uuid)

	// Validate server exists
	sm.mu.RLock()
	_, ok := sm.servers[uuid]
	sm.mu.RUnlock()
	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Parse request
	var req CopyFileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Destination == "" {
		http.Error(w, "destination is required", http.StatusBadRequest)
		return
	}

	// Resolve paths
	srcPath, err := sm.resolvePath(serverDir, requestedPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	destPath, err := sm.resolvePath(serverDir, req.Destination)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check source exists
	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Source path not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to access source path", http.StatusInternalServerError)
		}
		return
	}

	// Determine if destination should be treated as a directory
	destIsDir := false
	destInfo, err := os.Stat(destPath)
	if err == nil {
		destIsDir = destInfo.IsDir()
	} else if os.IsNotExist(err) {
		// If destination ends with / or source is a file and dest has no extension, treat as directory
		if strings.HasSuffix(req.Destination, "/") {
			destIsDir = true
		} else if !srcInfo.IsDir() && filepath.Ext(destPath) == "" && filepath.Ext(srcPath) != "" {
			destIsDir = true
		}
	}

	if destIsDir {
		// Create the directory if it doesn't exist
		if err := os.MkdirAll(destPath, 0755); err != nil {
			http.Error(w, "Failed to create destination directory", http.StatusInternalServerError)
			return
		}
		// Copy into the directory, keeping the original name
		destPath = filepath.Join(destPath, filepath.Base(srcPath))
	}

	// Check destination doesn't already exist
	if _, err := os.Stat(destPath); err == nil {
		http.Error(w, "Destination already exists", http.StatusConflict)
		return
	}

	// Prevent copying a directory into itself
	if srcInfo.IsDir() {
		absSrcPath, _ := filepath.Abs(srcPath)
		absDestPath, _ := filepath.Abs(destPath)
		if strings.HasPrefix(absDestPath, absSrcPath+string(filepath.Separator)) {
			http.Error(w, "Cannot copy directory into itself", http.StatusBadRequest)
			return
		}
	}

	// Ensure parent directory exists
	parentDir := filepath.Dir(destPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		http.Error(w, "Failed to create parent directory", http.StatusInternalServerError)
		return
	}

	// Perform the copy
	if srcInfo.IsDir() {
		if err := sm.copyDirectory(srcPath, destPath); err != nil {
			http.Error(w, fmt.Sprintf("Failed to copy directory: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		if err := sm.copyFileContents(srcPath, destPath); err != nil {
			http.Error(w, fmt.Sprintf("Failed to copy file: %v", err), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusCreated)
}

// copyFileContents copies a single file
func (sm *ServerManager) copyFileContents(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// copyDirectory recursively copies a directory
func (sm *ServerManager) copyDirectory(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	// Create destination directory
	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := sm.copyDirectory(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := sm.copyFileContents(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// getMimeType returns a simple mime type based on file extension
func getMimeType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".txt":
		return "text/plain"
	case ".json":
		return "application/json"
	case ".yml", ".yaml":
		return "text/yaml"
	case ".xml":
		return "application/xml"
	case ".properties":
		return "text/x-java-properties"
	case ".toml":
		return "application/toml"
	case ".cfg", ".conf", ".ini":
		return "text/plain"
	case ".sh", ".bash":
		return "application/x-sh"
	case ".jar":
		return "application/java-archive"
	case ".zip":
		return "application/zip"
	case ".gz", ".tar":
		return "application/gzip"
	case ".log":
		return "text/x-log"
	case ".md":
		return "text/markdown"
	default:
		return "application/octet-stream"
	}
}
