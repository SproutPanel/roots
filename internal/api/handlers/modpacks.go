package handlers

import (
	"archive/zip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ModpackFile is a single file the daemon downloads into the server directory
// during modpack provisioning. Hash fields are optional; when present the
// download is verified against them (sha1 preferred, then sha512, then md5).
type ModpackFile struct {
	Path   string `json:"path"` // relative to server dir, e.g. "mods/sodium.jar"
	URL    string `json:"url"`
	Sha1   string `json:"sha1,omitempty"`
	Sha512 string `json:"sha512,omitempty"`
	Md5    string `json:"md5,omitempty"`
	Size   int64  `json:"size,omitempty"`
}

// ModpackConfig describes the modpack provisioning phase that runs after the
// loader install script succeeds. Produced by the panel's ModpackResolver;
// the daemon never talks to the modpack source APIs directly.
type ModpackConfig struct {
	Source  string `json:"source"` // "curseforge", "modrinth", "ftb"
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`

	// File-list mode: explicit downloads (CurseForge manifest, FTB).
	Files []ModpackFile `json:"files,omitempty"`

	// Full-archive mode: download ArchiveURL and extract it into the server
	// dir. "curseforge_server_pack" strips a lone wrapper directory since
	// server packs are zipped both ways.
	ArchiveURL    string `json:"archive_url,omitempty"`
	ArchiveFormat string `json:"archive_format,omitempty"` // "curseforge_server_pack"

	// Overrides archive: a zip whose OverridesDir subdirectory (default
	// "overrides") is extracted on top of the server dir. For CurseForge this
	// is the client pack zip itself.
	OverridesArchiveURL string `json:"overrides_archive_url,omitempty"`
	OverridesDir        string `json:"overrides_dir,omitempty"`
}

// wrapperDirAllowlist are top-level directories that legitimately appear alone
// at the root of a server pack; a zip whose only top-level entry is one of
// these is NOT treated as having a wrapper directory to strip.
var wrapperDirAllowlist = map[string]bool{
	"mods": true, "config": true, "world": true, "libraries": true,
	"plugins": true, "scripts": true, "kubejs": true, "defaultconfigs": true,
	"resourcepacks": true, "datapacks": true,
}

// provisionModpack runs the modpack provisioning phase. It must be called
// after the install script has succeeded and before ownership is fixed, so
// provisioned files are chowned with everything else. The returned error is
// user-facing (passed to setFailed).
func (sm *ServerManager) provisionModpack(server *Server, serverDir string) error {
	mp := server.Modpack
	if mp == nil {
		return nil
	}

	sm.logger.Info("provisioning modpack", "uuid", server.UUID, "source", mp.Source, "name", mp.Name, "files", len(mp.Files))

	if err := sm.checkModpackDiskSpace(server, serverDir); err != nil {
		return err
	}

	client := &http.Client{Timeout: 15 * time.Minute}

	if mp.ArchiveURL != "" {
		sm.reportStatusToPanel(server.UUID, "installing", fmt.Sprintf("Downloading modpack archive: %s", mp.Name))
		stripWrapper := mp.ArchiveFormat == "curseforge_server_pack"
		if err := downloadAndExtractZip(client, mp.ArchiveURL, serverDir, "", stripWrapper); err != nil {
			return fmt.Errorf("modpack archive: %v", err)
		}
	}

	total := len(mp.Files)
	for i, f := range mp.Files {
		if err := downloadModpackFile(client, serverDir, f); err != nil {
			return fmt.Errorf("modpack file %s: %v", f.Path, err)
		}
		if (i+1)%25 == 0 || i+1 == total {
			sm.reportStatusToPanel(server.UUID, "installing", fmt.Sprintf("Downloading mods (%d/%d)", i+1, total))
		}
	}

	if mp.OverridesArchiveURL != "" {
		overridesDir := mp.OverridesDir
		if overridesDir == "" {
			overridesDir = "overrides"
		}
		sm.reportStatusToPanel(server.UUID, "installing", "Applying modpack overrides")
		if err := downloadAndExtractZip(client, mp.OverridesArchiveURL, serverDir, overridesDir, false); err != nil {
			return fmt.Errorf("modpack overrides: %v", err)
		}
	}

	sm.logger.Info("modpack provisioning complete", "uuid", server.UUID, "name", mp.Name)
	return nil
}

// checkModpackDiskSpace fails fast when the declared modpack file sizes would
// exceed the server's disk limit. Archives don't declare sizes, so this is a
// best-effort guard, not full enforcement.
func (sm *ServerManager) checkModpackDiskSpace(server *Server, serverDir string) error {
	if server.DiskLimit <= 0 {
		return nil
	}
	var declared int64
	for _, f := range server.Modpack.Files {
		declared += f.Size
	}
	if declared == 0 {
		return nil
	}
	used := int64(getDirSize(serverDir))
	if used+declared > server.DiskLimit {
		return fmt.Errorf("modpack needs %d MB but only %d MB of the disk limit remains",
			declared/1024/1024, (server.DiskLimit-used)/1024/1024)
	}
	return nil
}

// downloadModpackFile downloads one file into the server dir, verifying its
// hash when one is declared.
func downloadModpackFile(client *http.Client, serverDir string, f ModpackFile) error {
	destPath, err := secureModpackPath(serverDir, f.Path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	resp, err := client.Get(f.URL)
	if err != nil {
		return fmt.Errorf("download failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	var hasher hash.Hash
	var expected string
	switch {
	case f.Sha1 != "":
		hasher, expected = sha1.New(), f.Sha1
	case f.Sha512 != "":
		hasher, expected = sha512.New(), f.Sha512
	case f.Md5 != "":
		hasher, expected = md5.New(), f.Md5
	}

	file, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}

	var w io.Writer = file
	if hasher != nil {
		w = io.MultiWriter(file, hasher)
	}
	if _, err := io.Copy(w, resp.Body); err != nil {
		file.Close()
		os.Remove(destPath)
		return fmt.Errorf("download failed: %v", err)
	}
	file.Close()

	if hasher != nil {
		calculated := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(calculated, expected) {
			os.Remove(destPath)
			return fmt.Errorf("hash mismatch: expected %s, got %s", expected, calculated)
		}
	}
	return nil
}

// downloadAndExtractZip downloads a zip to a temp file and extracts it into
// serverDir. When subdir is non-empty only entries under that directory are
// extracted (with the prefix stripped). When stripWrapper is true and the
// archive's entries all live under a single non-standard top-level directory,
// that wrapper directory is stripped.
func downloadAndExtractZip(client *http.Client, url, serverDir, subdir string, stripWrapper bool) error {
	tmp, err := os.CreateTemp("", "roots-modpack-*.zip")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	resp, err := client.Get(url)
	if err != nil {
		tmp.Close()
		return fmt.Errorf("download failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		tmp.Close()
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return fmt.Errorf("download failed: %v", err)
	}
	tmp.Close()

	return extractZipInto(tmpPath, serverDir, subdir, stripWrapper)
}

func extractZipInto(zipPath, serverDir, subdir string, stripWrapper bool) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open archive: %v", err)
	}
	defer reader.Close()

	prefix := ""
	if subdir != "" {
		prefix = subdir + "/"
	} else if stripWrapper {
		prefix = detectWrapperDir(reader.File)
	}

	extracted := 0
	for _, entry := range reader.File {
		name := entry.Name
		if strings.HasPrefix(name, "__MACOSX/") {
			continue
		}
		if prefix != "" {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			name = strings.TrimPrefix(name, prefix)
		}
		if name == "" {
			continue
		}

		destPath, err := secureModpackPath(serverDir, name)
		if err != nil {
			return fmt.Errorf("archive entry %q: %v", entry.Name, err)
		}

		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, 0755); err != nil {
				return fmt.Errorf("failed to create directory: %v", err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory: %v", err)
		}
		src, err := entry.Open()
		if err != nil {
			return fmt.Errorf("failed to read archive entry %q: %v", entry.Name, err)
		}
		mode := entry.Mode() & 0777
		if mode == 0 {
			mode = 0644
		}
		dst, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			src.Close()
			return fmt.Errorf("failed to create file: %v", err)
		}
		_, copyErr := io.Copy(dst, src)
		src.Close()
		dst.Close()
		if copyErr != nil {
			return fmt.Errorf("failed to extract %q: %v", entry.Name, copyErr)
		}
		extracted++
	}

	if extracted == 0 && subdir != "" {
		// Not fatal: some packs ship no overrides directory at all.
		return nil
	}
	if extracted == 0 {
		return fmt.Errorf("archive contained no extractable files")
	}
	return nil
}

// detectWrapperDir returns "Wrapper/" when every entry in the archive lives
// under a single top-level directory that isn't a standard server directory
// (some CurseForge server packs zip a wrapper folder, some zip contents at
// the root).
func detectWrapperDir(entries []*zip.File) string {
	top := ""
	for _, entry := range entries {
		name := entry.Name
		if strings.HasPrefix(name, "__MACOSX/") {
			continue
		}
		idx := strings.Index(name, "/")
		if idx < 0 {
			return "" // file at root, nothing to strip
		}
		dir := name[:idx]
		if top == "" {
			top = dir
		} else if top != dir {
			return ""
		}
	}
	if top == "" || wrapperDirAllowlist[strings.ToLower(top)] {
		return ""
	}
	return top + "/"
}

// secureModpackPath resolves a manifest-supplied relative path inside the
// server dir, rejecting traversal and writes into the daemon's .roots
// metadata directory. Stricter than resolvePath: the prefix check is
// separator-bounded.
func secureModpackPath(serverDir, requestedPath string) (string, error) {
	cleanPath := filepath.Clean(requestedPath)
	if filepath.IsAbs(cleanPath) {
		// Manifest paths are relative by contract; anchor a stray leading
		// slash inside the server dir rather than honoring it.
		cleanPath = filepath.Clean(strings.TrimPrefix(cleanPath, string(os.PathSeparator)))
	}
	if cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path traversal detected")
	}
	fullPath := filepath.Join(serverDir, cleanPath)

	absServerDir, err := filepath.Abs(serverDir)
	if err != nil {
		return "", fmt.Errorf("path traversal detected")
	}
	absFullPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", fmt.Errorf("path traversal detected")
	}
	if absFullPath != absServerDir && !strings.HasPrefix(absFullPath, absServerDir+string(os.PathSeparator)) {
		return "", fmt.Errorf("path traversal detected")
	}

	rel, err := filepath.Rel(absServerDir, absFullPath)
	if err != nil {
		return "", fmt.Errorf("path traversal detected")
	}
	if rel == ".roots" || strings.HasPrefix(rel, ".roots"+string(os.PathSeparator)) {
		return "", fmt.Errorf("refusing to write into .roots metadata directory")
	}

	return absFullPath, nil
}
