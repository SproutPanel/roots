package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"github.com/sproutpanel/roots/internal/config"
	"github.com/sproutpanel/roots/internal/version"
)

// ReleaseInfo represents version information from the panel
type ReleaseInfo struct {
	Version     string            `json:"version"`
	ReleaseDate string            `json:"release_date"`
	Changelog   string            `json:"changelog,omitempty"`
	Downloads   map[string]string `json:"downloads"` // platform -> URL
	Checksums   map[string]string `json:"checksums"` // platform -> SHA256
	MinVersion  string            `json:"min_version,omitempty"` // minimum version for this update path
}

func updateCmd() *cobra.Command {
	var checkOnly bool
	var force bool
	var channel string

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Check for and install updates",
		Long: `Check for updates to the Roots daemon and optionally install them.

By default, this command will check for updates and prompt before installing.
Use --check to only check without installing.
Use --force to skip the confirmation prompt.

Examples:
  roots update           # Check and install updates (with confirmation)
  roots update --check   # Only check for updates
  roots update --force   # Install updates without confirmation`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(checkOnly, force, channel)
		},
	}

	cmd.Flags().BoolVar(&checkOnly, "check", false, "Only check for updates, don't install")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Install updates without confirmation")
	cmd.Flags().StringVar(&channel, "channel", "stable", "Update channel (stable, beta)")

	return cmd
}

func runUpdate(checkOnly, force bool, channel string) error {
	// Styles
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	successStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warningStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))

	fmt.Println(titleStyle.Render("Roots Update"))
	fmt.Println(dimStyle.Render("Current version: " + version.Version))
	fmt.Println()

	// Load config to get panel URL
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Check for updates
	fmt.Println("Checking for updates...")
	release, err := checkForUpdates(cfg.Panel.URL, channel)
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	// Compare versions
	if !isNewerVersion(version.Version, release.Version) {
		fmt.Println(successStyle.Render("✓ You are running the latest version"))
		return nil
	}

	// New version available
	fmt.Println(successStyle.Render(fmt.Sprintf("✓ New version available: %s", release.Version)))
	if release.ReleaseDate != "" {
		fmt.Println(dimStyle.Render("  Released: " + release.ReleaseDate))
	}
	if release.Changelog != "" {
		fmt.Println()
		renderChangelog(release.Changelog)
	}
	fmt.Println()

	if checkOnly {
		fmt.Println(warningStyle.Render("Run 'roots update' to install this update"))
		return nil
	}

	// Check minimum version requirement
	if release.MinVersion != "" && !isNewerOrEqual(version.Version, release.MinVersion) {
		return fmt.Errorf("this update requires version %s or higher. Please update incrementally", release.MinVersion)
	}

	// Get platform-specific download URL
	platform := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	downloadURL, ok := release.Downloads[platform]
	if !ok {
		fmt.Println(warningStyle.Render("No pre-built binary available for " + platform))
		fmt.Println()
		fmt.Println("You can build from source:")
		fmt.Println(dimStyle.Render("  git clone https://github.com/sproutpanel/roots.git"))
		fmt.Println(dimStyle.Render("  cd roots && git checkout v" + release.Version))
		fmt.Println(dimStyle.Render("  make build"))
		fmt.Println(dimStyle.Render("  sudo make install"))
		fmt.Println()
		return nil
	}

	// Confirm update
	if !force {
		fmt.Printf("Install update %s -> %s? [y/N]: ", version.Version, release.Version)
		var confirm string
		fmt.Scanln(&confirm)
		if !strings.HasPrefix(strings.ToLower(confirm), "y") {
			fmt.Println("Update cancelled")
			return nil
		}
	}

	// Download the update
	fmt.Println()
	fmt.Println("Downloading update...")

	tmpFile, err := downloadUpdate(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}
	defer os.Remove(tmpFile)

	// Verify checksum if available
	if checksum, ok := release.Checksums[platform]; ok {
		fmt.Println("Verifying checksum...")
		if err := verifyChecksum(tmpFile, checksum); err != nil {
			return fmt.Errorf("checksum verification failed: %w", err)
		}
		fmt.Println(successStyle.Render("✓ Checksum verified"))
	}

	// Get current executable path
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	// Install the update
	fmt.Println("Installing update...")
	if err := installUpdate(tmpFile, execPath); err != nil {
		return fmt.Errorf("failed to install update: %w", err)
	}

	fmt.Println()
	fmt.Println(successStyle.Render("✓ Update installed successfully!"))
	fmt.Println()
	fmt.Println(dimStyle.Render("If roots is running as a service, restart it with:"))
	fmt.Println("  sudo systemctl restart roots")
	fmt.Println()

	// Check if we're running as a daemon and should restart
	if isRunningAsService() {
		fmt.Println(warningStyle.Render("Note: The daemon is running. Restart to apply the update."))
	}

	return nil
}

func checkForUpdates(panelURL, channel string) (*ReleaseInfo, error) {
	url := fmt.Sprintf("%s/api/releases/latest", strings.TrimSuffix(panelURL, "/"))
	if channel != "stable" {
		url = fmt.Sprintf("%s?channel=%s", url, channel)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to panel: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("panel returned status %d", resp.StatusCode)
	}

	var release ReleaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to parse release info: %w", err)
	}

	return &release, nil
}

func downloadUpdate(url string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	// Create temp file
	tmpFile, err := os.CreateTemp("", "roots-update-*")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	// Copy with progress indication
	size := resp.ContentLength
	var written int64
	buf := make([]byte, 32*1024)
	lastPercent := -1

	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := tmpFile.Write(buf[:n]); werr != nil {
				os.Remove(tmpFile.Name())
				return "", werr
			}
			written += int64(n)

			if size > 0 {
				percent := int(float64(written) / float64(size) * 100)
				if percent != lastPercent && percent%10 == 0 {
					fmt.Printf("  %d%%\n", percent)
					lastPercent = percent
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			os.Remove(tmpFile.Name())
			return "", err
		}
	}

	return tmpFile.Name(), nil
}

func verifyChecksum(filePath, expectedChecksum string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	actualChecksum := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actualChecksum, expectedChecksum) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}

	return nil
}

func installUpdate(tmpFile, execPath string) error {
	// Check if the downloaded file is a tarball or raw binary
	f, err := os.Open(tmpFile)
	if err != nil {
		return err
	}

	// Read magic bytes to detect gzip
	magic := make([]byte, 2)
	_, err = f.Read(magic)
	f.Close()
	if err != nil {
		return err
	}

	var newBinaryPath string

	// Check for gzip magic bytes (0x1f 0x8b)
	if magic[0] == 0x1f && magic[1] == 0x8b {
		// It's a gzipped tarball, extract the binary
		extracted, err := extractBinary(tmpFile)
		if err != nil {
			return fmt.Errorf("failed to extract binary: %w", err)
		}
		newBinaryPath = extracted
		defer os.Remove(newBinaryPath)
	} else {
		// It's a raw binary
		newBinaryPath = tmpFile
	}

	// Get file info for permissions
	info, err := os.Stat(execPath)
	if err != nil {
		return err
	}

	// Create backup of current binary
	backupPath := execPath + ".bak"
	if err := copyFile(execPath, backupPath); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Replace the binary
	// First, try to rename (atomic on same filesystem)
	if err := os.Rename(newBinaryPath, execPath); err != nil {
		// Rename failed, try copy instead
		if err := copyFile(newBinaryPath, execPath); err != nil {
			// Restore backup
			os.Rename(backupPath, execPath)
			return fmt.Errorf("failed to install binary: %w", err)
		}
	}

	// Set permissions
	if err := os.Chmod(execPath, info.Mode()); err != nil {
		// Non-fatal, just warn
		fmt.Printf("Warning: failed to set permissions: %v\n", err)
	}

	// Clean up backup after successful install
	os.Remove(backupPath)

	return nil
}

func extractBinary(tarballPath string) (string, error) {
	f, err := os.Open(tarballPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	// Look for the roots binary in the tarball
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		// Look for the roots binary (might be at root or in a directory)
		name := filepath.Base(header.Name)
		if name == "roots" && header.Typeflag == tar.TypeReg {
			tmpFile, err := os.CreateTemp("", "roots-binary-*")
			if err != nil {
				return "", err
			}

			if _, err := io.Copy(tmpFile, tr); err != nil {
				tmpFile.Close()
				os.Remove(tmpFile.Name())
				return "", err
			}

			tmpFile.Close()
			os.Chmod(tmpFile.Name(), 0755)
			return tmpFile.Name(), nil
		}
	}

	return "", fmt.Errorf("roots binary not found in tarball")
}

func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

// isNewerVersion returns true if newVer is newer than currentVer
// Versions are expected in semver format: v1.2.3 or 1.2.3
func isNewerVersion(currentVer, newVer string) bool {
	current := parseVersion(currentVer)
	new := parseVersion(newVer)

	for i := 0; i < 3; i++ {
		if new[i] > current[i] {
			return true
		}
		if new[i] < current[i] {
			return false
		}
	}
	return false
}

// isNewerOrEqual returns true if currentVer >= minVer
func isNewerOrEqual(currentVer, minVer string) bool {
	current := parseVersion(currentVer)
	min := parseVersion(minVer)

	for i := 0; i < 3; i++ {
		if current[i] > min[i] {
			return true
		}
		if current[i] < min[i] {
			return false
		}
	}
	return true // equal
}

func parseVersion(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	v = strings.Split(v, "-")[0] // Remove pre-release suffix

	var parts [3]int
	for i, p := range strings.Split(v, ".") {
		if i >= 3 {
			break
		}
		fmt.Sscanf(p, "%d", &parts[i])
	}
	return parts
}

func isRunningAsService() bool {
	// Check if we're running under systemd
	if os.Getenv("INVOCATION_ID") != "" {
		return true
	}
	// Check if parent is systemd (PID 1)
	ppid := syscall.Getppid()
	return ppid == 1
}

// renderChangelog renders the changelog as styled markdown
func renderChangelog(changelog string) {
	// Wrap in a "Changelog" header for better presentation
	md := "## Changelog\n\n" + changelog

	// Create a glamour renderer with auto style (adapts to terminal background)
	renderer, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(80),
	)
	if err != nil {
		// Fallback to plain text
		fmt.Println("Changelog:")
		for _, line := range strings.Split(changelog, "\n") {
			fmt.Println("  " + line)
		}
		return
	}

	out, err := renderer.Render(md)
	if err != nil {
		// Fallback to plain text
		fmt.Println("Changelog:")
		for _, line := range strings.Split(changelog, "\n") {
			fmt.Println("  " + line)
		}
		return
	}

	fmt.Print(out)
}
