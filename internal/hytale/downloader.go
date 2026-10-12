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
	"regexp"
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

	// DownloaderTimeout is the maximum time for one downloader run. It covers the
	// 15 minute device code window plus downloading several GB of server files.
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
	Success      bool
	Version      string
	AuthRequired bool
	AuthURL      string
	AuthCode     string
	Error        string
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
	return d.runDownloader(ctx, serverDir, modeDownload, patchline, callback)
}

// CheckVersion returns the latest Hytale server version available on the patchline without downloading
func (d *DownloaderClient) CheckVersion(ctx context.Context, serverDir, patchline string, callback OutputCallback) (string, error) {
	result, err := d.runDownloader(ctx, serverDir, modePrintVersion, patchline, callback)
	if err != nil {
		return "", err
	}
	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}
	if result.Version == "" {
		return "", fmt.Errorf("could not determine latest Hytale version from downloader output")
	}
	return result.Version, nil
}

// CheckUpdate checks if there's a newer version available on the patchline
func (d *DownloaderClient) CheckUpdate(ctx context.Context, serverDir, patchline string, callback OutputCallback) (bool, string, error) {
	// Get the installed version from our marker file
	installedVersion, err := d.GetInstalledVersion(serverDir)
	if err != nil {
		return false, "", fmt.Errorf("failed to get installed version: %w", err)
	}

	// Get the latest available version using -print-version
	latestVersion, err := d.CheckVersion(ctx, serverDir, patchline, callback)
	if err != nil {
		return false, installedVersion, fmt.Errorf("failed to check latest version: %w", err)
	}

	// Compare versions - update available if they differ
	updateAvailable := installedVersion != latestVersion
	return updateAvailable, latestVersion, nil
}

const (
	modeDownload     = "download"
	modePrintVersion = "print-version"

	// errorTailLines is how many trailing output lines are kept for error reports
	errorTailLines = 20
)

// versionPattern matches Hytale game versions like "2026.01.22-6f8bdbdc4"
var versionPattern = regexp.MustCompile(`\b(\d{4}\.\d{2}\.\d{2}-[0-9a-f]+)\b`)

// parseVersionLine extracts a game version from a line of downloader output.
// Lines about hytale-downloader itself (e.g. its self-update notice) are ignored.
func parseVersionLine(line string) string {
	if strings.Contains(strings.ToLower(line), "hytale-downloader") {
		return ""
	}
	if m := versionPattern.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return ""
}

// buildScript builds the shell script run inside the downloader container.
// Lines prefixed with "[Sprout] ERROR:" explain failures and are surfaced to the panel.
func (d *DownloaderClient) buildScript(mode, patchline string) string {
	downloaderArgs := "-skip-update-check"
	if mode == modePrintVersion {
		downloaderArgs += " -print-version"
	}
	if arg := d.buildPatchlineArg(patchline); arg != "" {
		downloaderArgs += " " + arg
	}

	script := fmt.Sprintf(`
cd /mnt/server || { echo "[Sprout] ERROR: server directory is not mounted"; exit 20; }

BIN=./%[1]s
FETCHED_MARKER=.hytale-downloader-fetched
CREDS=.hytale-downloader-credentials.json
AUTH_ERROR_PATTERN='%[5]s'

case "$(uname -m)" in
    x86_64|amd64) ;;
    *)
        echo "[Sprout] ERROR: hytale-downloader only ships for x86_64 Linux, but this node is $(uname -m)."
        exit 21
        ;;
esac

fetch_downloader() {
    echo "Downloading hytale-downloader..."
    rm -f hytale-downloader.zip
    if ! wget -q -O hytale-downloader.zip "%[2]s"; then
        echo "[Sprout] ERROR: could not download hytale-downloader from %[2]s"
        rm -f hytale-downloader.zip
        return 1
    fi
    if ! unzip -o -q hytale-downloader.zip "%[1]s"; then
        echo "[Sprout] ERROR: could not unpack hytale-downloader.zip"
        rm -f hytale-downloader.zip
        return 1
    fi
    rm -f hytale-downloader.zip
    chmod +x "$BIN"
    date +%%s > "$FETCHED_MARKER"
}

# Fetch the downloader if missing, and refresh it weekly so we don't run a stale build
if [ ! -x "$BIN" ]; then
    fetch_downloader || exit 22
elif [ -z "$(find "$FETCHED_MARKER" -mtime -7 2>/dev/null)" ]; then
    echo "Refreshing hytale-downloader..."
    fetch_downloader || echo "Refresh failed, continuing with the existing hytale-downloader"
fi

if [ -f "$CREDS" ]; then
    echo "Using cached Hytale credentials..."
fi

run_downloader() {
    echo "Running hytale-downloader..."
    { "$BIN" %[3]s 2>&1; echo $? > .hytale-downloader.rc; } | tee .hytale-downloader.log
    rc=$(cat .hytale-downloader.rc 2>/dev/null || echo 1)
    rm -f .hytale-downloader.rc
    return "$rc"
}

run_downloader
rc=$?

# Invalid or expired cached credentials: drop them and retry once so a fresh
# device code is printed. Also do this when the credentials file is over 30 days
# old, since its refresh token has likely expired even if the error is unclear.
if [ "$rc" -ne 0 ] && [ -f "$CREDS" ]; then
    stale_creds=""
    [ -z "$(find "$CREDS" -mtime -30 2>/dev/null)" ] && stale_creds=1
    if [ -n "$stale_creds" ] || grep -qiE "$AUTH_ERROR_PATTERN" .hytale-downloader.log; then
        echo "Cached Hytale credentials were rejected or are stale, clearing them and re-authenticating..."
        rm -f "$CREDS"
        run_downloader
        rc=$?
    fi
fi

if [ "$rc" -ne 0 ]; then
    if grep -qiE "(device|user|authori[sz]ation).{0,40}(code)?.{0,20}(expired|timed? ?out)" .hytale-downloader.log; then
        echo "[Sprout] ERROR: the Hytale login code expired before it was approved. Retry and approve the code within 15 minutes."
    elif grep -qiE "$AUTH_ERROR_PATTERN" .hytale-downloader.log; then
        echo "[Sprout] ERROR: Hytale rejected the login. Retry to get a new login code."
    elif grep -qiE "404|not found" .hytale-downloader.log; then
        echo "[Sprout] ERROR: Hytale files not found. Check the patchline (%[4]s) and that the account owns Hytale."
    elif grep -qiE "checksum" .hytale-downloader.log; then
        echo "[Sprout] ERROR: downloaded files failed checksum verification. Retry the install."
    elif grep -qiE "no space|disk full" .hytale-downloader.log; then
        echo "[Sprout] ERROR: the node is out of disk space."
    fi
    echo "[Sprout] ERROR: hytale-downloader exited with code $rc"
    rm -f .hytale-downloader.log
    exit "$rc"
fi
rm -f .hytale-downloader.log
`, DownloaderBinary, DownloaderURL, downloaderArgs, patchlineOrDefault(patchline), authErrorPattern)

	if mode == modeDownload {
		script += `
# Extract the downloaded server zip. The downloader names it after the version,
# e.g. "2026.01.13-dcad8778f.zip"; the newest sorts last.
newest_zip=""
for f in [0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9]-*.zip; do
    [ -f "$f" ] && newest_zip="$f"
done

if [ -z "$newest_zip" ]; then
    echo "[Sprout] ERROR: hytale-downloader finished but no server zip was found"
    exit 23
fi

echo "Extracting server files from $newest_zip..."
if ! unzip -o -q "$newest_zip"; then
    echo "[Sprout] ERROR: failed to extract $newest_zip (is the node out of disk space?)"
    exit 24
fi
if [ ! -f Server/HytaleServer.jar ]; then
    echo "[Sprout] ERROR: $newest_zip did not contain Server/HytaleServer.jar"
    exit 25
fi
echo "Server files extracted successfully"

version="${newest_zip%.zip}"
echo "$version" > .hytale_version
echo "Saved version: $version"

# The zips are several GB each and no longer needed once extracted
for f in [0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9]-*.zip; do
    [ -f "$f" ] && rm -f "$f"
done
true
`
	}
	return script
}

// authErrorPattern (grep -iE) matches downloader output meaning the cached
// credentials are no longer usable: HTTP 401/403, OAuth invalid_grant, or
// expired/invalid/revoked token wording. Kept broad on purpose since a false
// positive only costs a re-login.
const authErrorPattern = `(^|[^0-9a-f])40[13]([^0-9a-f]|$)|unauthori[sz]ed|forbidden|invalid[ _-]?(grant|token|credentials?|client)|(token|credential|session|refresh|auth).{0,60}(expired|invalid|revoked|rejected)|(expired|invalid|revoked).{0,60}(token|credential|session)|re-?authenticate|login required|not (logged in|authenticated)`

// patchlineOrDefault returns the patchline name, defaulting to "release" when unset or unsafe
func patchlineOrDefault(patchline string) string {
	if patchline == "" || !patchlinePattern.MatchString(patchline) {
		return "release"
	}
	return patchline
}

// runDownloader executes the hytale-downloader in a Docker container
func (d *DownloaderClient) runDownloader(ctx context.Context, serverDir, mode, patchline string, callback OutputCallback) (*DownloadResult, error) {
	ctx, cancel := context.WithTimeout(ctx, DownloaderTimeout)
	defer cancel()

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

	// Create container config
	config := &container.Config{
		Image: d.image,
		Cmd:   []string{"/bin/sh", "-c", d.buildScript(mode, patchline)},
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

	// Unblock the output reader if the timeout fires while the downloader is
	// still running (e.g. waiting on a device code nobody approves)
	go func() {
		<-ctx.Done()
		attachResp.Close()
	}()

	// Process output
	result := &DownloadResult{Success: true}
	tracker := &hytale.AuthPromptTracker{}
	var tail []string      // last errorTailLines lines of output
	var explained []string // "[Sprout] ERROR:" lines from the script

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

		tail = append(tail, line)
		if len(tail) > errorTailLines {
			tail = tail[1:]
		}
		if msg, ok := strings.CutPrefix(line, "[Sprout] ERROR: "); ok {
			explained = append(explained, msg)
		}

		// Parse for events
		event := tracker.ProcessLine(line)

		// Check for auth prompt
		if event != nil && event.Type == hytale.EventAuthPrompt {
			result.AuthRequired = true
			result.AuthURL = event.URL
			result.AuthCode = event.Code
		}

		// Check for version in output (last match wins, e.g. "Saved version: ...")
		if v := parseVersionLine(line); v != "" {
			result.Version = v
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
			if ctx.Err() == context.DeadlineExceeded {
				return nil, fmt.Errorf("hytale-downloader timed out after %s (was the login code approved?)", DownloaderTimeout)
			}
			return nil, fmt.Errorf("error waiting for container: %w", err)
		}
	case status := <-statusCh:
		if status.StatusCode != 0 {
			result.Success = false
			result.Error = formatDownloaderError(status.StatusCode, explained, tail)
			if status.Error != nil {
				result.Error = status.Error.Message + "\n" + result.Error
			}
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return result, nil
}

// formatDownloaderError builds an error message for a failed downloader run,
// leading with the script's explanation when it gave one and ending with the
// last lines of output so the panel shows the real cause
func formatDownloaderError(exitCode int64, explained, tail []string) string {
	msg := fmt.Sprintf("downloader exited with code %d", exitCode)
	if len(explained) > 0 {
		msg = strings.Join(explained, "; ")
	}
	if len(tail) > 0 {
		msg += "\n\nLast output:\n" + strings.Join(tail, "\n")
	}
	return msg
}

// patchlinePattern restricts patchline names since they are interpolated into a shell script
var patchlinePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// buildPatchlineArg builds the patchline argument if specified
func (d *DownloaderClient) buildPatchlineArg(patchline string) string {
	if patchline == "" || patchline == "release" || !patchlinePattern.MatchString(patchline) {
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
