package hytale

import (
	"os/exec"
	"strings"
	"testing"
)

func TestParseVersionLine(t *testing.T) {
	tests := map[string]string{
		"2026.01.22-6f8bdbdc4":                                     "2026.01.22-6f8bdbdc4",
		"Saved version: 2026.01.13-dcad8778f":                      "2026.01.13-dcad8778f",
		"Extracting server files from 2026.01.13-dcad8778f.zip...": "2026.01.13-dcad8778f",
		"A new version of hytale-downloader is available: 2026.01.31-abc1234 (current: 2026.01.15-def5678)": "",
		"Running hytale-downloader...": "",
		"Checking version: unknown":    "",
	}
	for line, want := range tests {
		if got := parseVersionLine(line); got != want {
			t.Errorf("parseVersionLine(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestFormatDownloaderError(t *testing.T) {
	msg := formatDownloaderError(1, []string{"Hytale rejected the login. Retry to get a new login code."}, []string{"error: 401 Unauthorized"})
	if !strings.HasPrefix(msg, "Hytale rejected the login.") || !strings.Contains(msg, "401 Unauthorized") {
		t.Errorf("unexpected message %q", msg)
	}

	msg = formatDownloaderError(1, nil, []string{"boom"})
	if !strings.HasPrefix(msg, "downloader exited with code 1") || !strings.Contains(msg, "boom") {
		t.Errorf("unexpected message %q", msg)
	}
}

func TestBuildScript(t *testing.T) {
	d := &DownloaderClient{}

	download := d.buildScript(modeDownload, "pre-release")
	if !strings.Contains(download, "-skip-update-check -patchline pre-release") {
		t.Error("download script should skip the self-update check and pass the patchline")
	}
	if !strings.Contains(download, "Extracting server files") {
		t.Error("download script should extract the server zip")
	}

	printVersion := d.buildScript(modePrintVersion, "pre-release")
	if !strings.Contains(printVersion, "-skip-update-check -print-version -patchline pre-release") {
		t.Error("print-version script should pass the patchline")
	}
	if strings.Contains(printVersion, "Extracting server files") {
		t.Error("print-version script should not extract anything")
	}

	if strings.Contains(d.buildScript(modeDownload, "x; rm -rf /"), "rm -rf /") {
		t.Error("unsafe patchline should not be interpolated")
	}

	for _, script := range []string{download, printVersion} {
		if out, err := exec.Command("sh", "-n", "-c", script).CombinedOutput(); err != nil {
			t.Errorf("script has a syntax error: %v\n%s", err, out)
		}
	}
}
