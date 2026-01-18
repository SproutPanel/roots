// Package hytale provides node-level Hytale services including OAuth2 authentication
// and the hytale-downloader integration.
package hytale

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"

	"github.com/sproutpanel/roots/internal/games/hytale"
)

const (
	// DownloaderImage is the Docker image used to run hytale-downloader
	// Using pelican installers:alpine which has wget, unzip, and glibc compatibility
	DownloaderImage = "ghcr.io/pelican-eggs/installers:alpine"

	// DownloaderURL is where to download the hytale-downloader binary
	DownloaderURL = "https://downloader.hytale.com/hytale-downloader.zip"

	// DownloaderBinary is the name of the Linux binary inside the zip
	DownloaderBinary = "hytale-downloader-linux-amd64"

	// DownloaderTimeout is the maximum time to wait for a download operation
	DownloaderTimeout = 30 * time.Minute
)

// DownloaderClient wraps the hytale-downloader CLI tool running in Docker
type DownloaderClient struct {
	dockerClient *client.Client
	logger       *slog.Logger
	image        string
}

// DownloadResult contains the result of a download operation
type DownloadResult struct {
	Success     bool
	Version     string
	AuthRequired bool
	AuthURL     string
	AuthCode    string
	Error       string
}

// OutputCallback is called for each line of output from the downloader
type OutputCallback func(line string, event *hytale.ConsoleEvent)

// NewDownloaderClient creates a new downloader client
func NewDownloaderClient(dockerClient *client.Client, logger *slog.Logger) *DownloaderClient {
	return &DownloaderClient{
		dockerClient: dockerClient,
		logger:       logger,
		image:        DownloaderImage,
	}
}

// SetImage allows overriding the Docker image (useful for testing)
func (d *DownloaderClient) SetImage(image string) {
	d.image = image
}

// DownloadServer downloads Hytale server files to the specified directory
// The callback is invoked for each line of output, allowing real-time progress updates
// and auth prompt detection
func (d *DownloaderClient) DownloadServer(ctx context.Context, serverDir, patchline string, callback OutputCallback) (*DownloadResult, error) {
	return d.runDownloader(ctx, serverDir, []string{}, patchline, callback)
}

// CheckVersion checks the current Hytale server version without downloading
func (d *DownloaderClient) CheckVersion(ctx context.Context, serverDir string, callback OutputCallback) (string, error) {
	result, err := d.runDownloader(ctx, serverDir, []string{"-print-version"}, "", callback)
	if err != nil {
		return "", err
	}
	return result.Version, nil
}

// CheckUpdate checks if there's a newer version available
func (d *DownloaderClient) CheckUpdate(ctx context.Context, serverDir string, callback OutputCallback) (bool, string, error) {
	// Get the installed version from our marker file
	installedVersion, err := d.GetInstalledVersion(serverDir)
	if err != nil {
		return false, "", fmt.Errorf("failed to get installed version: %w", err)
	}

	// Get the latest available version using -print-version
	latestVersion, err := d.CheckVersion(ctx, serverDir, callback)
	if err != nil {
		return false, installedVersion, fmt.Errorf("failed to check latest version: %w", err)
	}

	// Compare versions - update available if they differ
	updateAvailable := installedVersion != latestVersion && latestVersion != ""
	return updateAvailable, latestVersion, nil
}

// runDownloader executes the hytale-downloader in a Docker container
func (d *DownloaderClient) runDownloader(ctx context.Context, serverDir string, args []string, patchline string, callback OutputCallback) (*DownloadResult, error) {
	// Ensure server directory exists
	if err := os.MkdirAll(serverDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create server directory: %w", err)
	}

	// Pull the image if it doesn't exist
	_, _, err := d.dockerClient.ImageInspectWithRaw(ctx, d.image)
	if err != nil {
		d.logger.Info("pulling downloader image", "image", d.image)
		reader, pullErr := d.dockerClient.ImagePull(ctx, d.image, types.ImagePullOptions{})
		if pullErr != nil {
			return nil, fmt.Errorf("failed to pull image %s: %w", d.image, pullErr)
		}
		io.Copy(io.Discard, reader)
		reader.Close()
	}

	// Build the command to run inside the container
	// 1. Download hytale-downloader if not present
	// 2. Make it executable
	// 3. Run it with the specified arguments
	// Note: The downloader automatically uses .hytale-downloader-credentials.json if present
	downloadCmd := fmt.Sprintf(`
set -e
cd /mnt/server

# Download hytale-downloader if not present
if [ ! -f ./%s ]; then
    echo "Downloading hytale-downloader..."
    wget -q -O hytale-downloader.zip "%s"
    unzip -o hytale-downloader.zip
    rm -f hytale-downloader.zip
    chmod +x ./%s
fi

# Check for cached credentials
if [ -f .hytale-downloader-credentials.json ]; then
    echo "Using cached Hytale credentials..."
fi

# Run the downloader
echo "Running hytale-downloader..."
./%s %s %s

# Extract the downloaded server zip if present
# The downloader creates files like "2026.01.13-dcad8778f.zip"
# Find server zips sorted by filename (which includes date, so newest is last alphabetically)
newest_zip=""
for f in [0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9]-*.zip; do
    [ -f "$f" ] && newest_zip="$f"
done

if [ -n "$newest_zip" ]; then
    echo "Extracting server files from $newest_zip..."
    unzip -o "$newest_zip"
    echo "Server files extracted successfully"
    # Save the version from the zip filename
    version="${newest_zip%%.zip}"
    echo "$version" > .hytale_version
    echo "Saved version: $version"
fi

# Clean up old zips, keep only the 2 most recent
# List zips in reverse order (newest first by filename)
zip_count=0
for f in $(ls -r [0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9]-*.zip 2>/dev/null); do
    [ -f "$f" ] || continue
    zip_count=$((zip_count + 1))
    if [ $zip_count -gt 2 ]; then
        echo "Removing old server zip: $f"
        rm -f "$f"
    fi
done
`, DownloaderBinary, DownloaderURL, DownloaderBinary, DownloaderBinary, strings.Join(args, " "), d.buildPatchlineArg(patchline))

	// Create container config
	config := &container.Config{
		Image: d.image,
		Cmd:   []string{"/bin/sh", "-c", downloadCmd},
		Tty:   false,
		Env:   []string{},
	}

	// Host config with server directory mounted
	hostConfig := &container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: serverDir,
				Target: "/mnt/server",
			},
		},
		// Force amd64 platform since hytale-downloader is Linux amd64 only
		// Note: This requires Docker with multi-platform support (buildx/qemu)
	}

	// Create the container
	resp, err := d.dockerClient.ContainerCreate(ctx, config, hostConfig, nil, nil, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}
	containerID := resp.ID

	// Ensure container is removed when done
	defer func() {
		removeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := d.dockerClient.ContainerRemove(removeCtx, containerID, types.ContainerRemoveOptions{Force: true}); err != nil {
			d.logger.Warn("Failed to remove container", "container", containerID, "error", err)
		}
	}()

	// Attach to container output before starting
	attachResp, err := d.dockerClient.ContainerAttach(ctx, containerID, types.ContainerAttachOptions{
		Stream: true,
		Stdout: true,
		Stderr: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach to container: %w", err)
	}
	defer attachResp.Close()

	// Start the container
	if err := d.dockerClient.ContainerStart(ctx, containerID, types.ContainerStartOptions{}); err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Process output
	result := &DownloadResult{Success: true}
	tracker := &hytale.AuthPromptTracker{}

	// Create pipes for demultiplexing Docker output
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		stdcopy.StdCopy(pw, pw, attachResp.Reader)
	}()

	// Read output line by line
	scanner := bufio.NewScanner(pr)
	for scanner.Scan() {
		line := scanner.Text()
		d.logger.Debug("Downloader output", "line", line)

		// Parse for events
		event := tracker.ProcessLine(line)

		// Check for auth prompt
		if event != nil && event.Type == hytale.EventAuthPrompt {
			result.AuthRequired = true
			result.AuthURL = event.URL
			result.AuthCode = event.Code
		}

		// Check for version in output
		if strings.HasPrefix(line, "Version:") || strings.Contains(line, "version") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.Version = strings.TrimSpace(parts[1])
			}
		}

		// Invoke callback
		if callback != nil {
			callback(line, event)
		}
	}

	// Wait for container to finish
	statusCh, errCh := d.dockerClient.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return nil, fmt.Errorf("error waiting for container: %w", err)
		}
	case status := <-statusCh:
		if status.StatusCode != 0 {
			result.Success = false
			result.Error = fmt.Sprintf("downloader exited with code %d", status.StatusCode)
			if status.Error != nil {
				result.Error = status.Error.Message
			}
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return result, nil
}

// buildPatchlineArg builds the patchline argument if specified
func (d *DownloaderClient) buildPatchlineArg(patchline string) string {
	if patchline == "" || patchline == "release" {
		return ""
	}
	return fmt.Sprintf("-patchline %s", patchline)
}

// GetInstalledVersion reads the installed server version from the server directory
func (d *DownloaderClient) GetInstalledVersion(serverDir string) (string, error) {
	// Look for version file or parse from server jar
	versionFile := filepath.Join(serverDir, ".hytale_version")
	data, err := os.ReadFile(versionFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // No version installed yet
		}
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// SaveInstalledVersion saves the installed version to a marker file
func (d *DownloaderClient) SaveInstalledVersion(serverDir, version string) error {
	versionFile := filepath.Join(serverDir, ".hytale_version")
	return os.WriteFile(versionFile, []byte(version), 0644)
}
