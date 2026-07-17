package handlers

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecureModpackPath(t *testing.T) {
	serverDir := t.TempDir()

	valid := []string{
		"mods/sodium.jar",
		"config/nested/deep.toml",
		"server.properties",
		"mods/../config/ok.toml", // cleans to config/ok.toml, still inside
	}
	for _, p := range valid {
		if _, err := secureModpackPath(serverDir, p); err != nil {
			t.Errorf("secureModpackPath(%q) unexpected error: %v", p, err)
		}
	}

	invalid := []string{
		"../../etc/passwd",
		"mods/../../outside.jar",
		".roots/server.json",
		".roots/install.sh",
	}
	for _, p := range invalid {
		if _, err := secureModpackPath(serverDir, p); err == nil {
			t.Errorf("secureModpackPath(%q) expected error, got nil", p)
		}
	}

	// Absolute paths are anchored inside the server dir, not honored as-is.
	got, err := secureModpackPath(serverDir, "/mods/abs.jar")
	if err != nil {
		t.Fatalf("absolute path: unexpected error: %v", err)
	}
	if want := filepath.Join(serverDir, "mods", "abs.jar"); got != want {
		t.Errorf("absolute path resolved to %q, want %q", got, want)
	}
}

func TestSecureModpackPathSiblingPrefix(t *testing.T) {
	// /srv/foo must not accept paths escaping into /srv/foobar.
	base := t.TempDir()
	serverDir := filepath.Join(base, "srv")
	if err := os.MkdirAll(serverDir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := secureModpackPath(serverDir, "../srvextra/file.jar"); err == nil {
		t.Error("sibling-prefix escape not rejected")
	}
}

func TestDownloadModpackFile(t *testing.T) {
	content := []byte("fake jar content")
	sum := sha1.Sum(content)
	sha1Hex := hex.EncodeToString(sum[:])

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing.jar" {
			http.NotFound(w, r)
			return
		}
		w.Write(content)
	}))
	defer ts.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	t.Run("verified download", func(t *testing.T) {
		serverDir := t.TempDir()
		f := ModpackFile{Path: "mods/test.jar", URL: ts.URL + "/test.jar", Sha1: sha1Hex}
		if err := downloadModpackFile(client, serverDir, f); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got, err := os.ReadFile(filepath.Join(serverDir, "mods", "test.jar"))
		if err != nil {
			t.Fatalf("file not written: %v", err)
		}
		if !bytes.Equal(got, content) {
			t.Error("written content does not match")
		}
	})

	t.Run("hash mismatch removes file", func(t *testing.T) {
		serverDir := t.TempDir()
		f := ModpackFile{Path: "mods/bad.jar", URL: ts.URL + "/bad.jar", Sha1: strings.Repeat("0", 40)}
		err := downloadModpackFile(client, serverDir, f)
		if err == nil || !strings.Contains(err.Error(), "hash mismatch") {
			t.Fatalf("expected hash mismatch error, got %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(serverDir, "mods", "bad.jar")); !os.IsNotExist(statErr) {
			t.Error("file with bad hash was not removed")
		}
	})

	t.Run("no hash skips verification", func(t *testing.T) {
		serverDir := t.TempDir()
		f := ModpackFile{Path: "mods/nohash.jar", URL: ts.URL + "/nohash.jar"}
		if err := downloadModpackFile(client, serverDir, f); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("http error", func(t *testing.T) {
		serverDir := t.TempDir()
		f := ModpackFile{Path: "mods/missing.jar", URL: ts.URL + "/missing.jar"}
		err := downloadModpackFile(client, serverDir, f)
		if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
			t.Fatalf("expected HTTP 404 error, got %v", err)
		}
	})

	t.Run("traversal rejected", func(t *testing.T) {
		serverDir := t.TempDir()
		f := ModpackFile{Path: "../escape.jar", URL: ts.URL + "/x.jar"}
		if err := downloadModpackFile(client, serverDir, f); err == nil {
			t.Fatal("expected traversal error")
		}
	})
}

// buildZip creates an in-memory zip with the given name -> content entries.
// Entries with a trailing slash become directories.
func buildZip(t *testing.T, entries map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		if strings.HasSuffix(name, "/") {
			if _, err := w.Create(name); err != nil {
				t.Fatal(err)
			}
			continue
		}
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "test.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractZipIntoOverrides(t *testing.T) {
	zipPath := buildZip(t, map[string]string{
		"manifest.json":                 `{"name":"pack"}`,
		"overrides/config/mod.toml":     "setting = true",
		"overrides/mods/included.jar":   "jar bytes",
		"overrides/server.properties":   "motd=hi",
		"__MACOSX/overrides/config/._x": "junk",
	})

	serverDir := t.TempDir()
	if err := extractZipInto(zipPath, serverDir, "overrides", false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, want := range []string{"config/mod.toml", "mods/included.jar", "server.properties"} {
		if _, err := os.Stat(filepath.Join(serverDir, want)); err != nil {
			t.Errorf("expected %s to be extracted: %v", want, err)
		}
	}
	// manifest.json is outside overrides/ and must not be extracted
	if _, err := os.Stat(filepath.Join(serverDir, "manifest.json")); !os.IsNotExist(err) {
		t.Error("manifest.json outside overrides/ was extracted")
	}
}

func TestExtractZipIntoMissingOverridesIsNotFatal(t *testing.T) {
	zipPath := buildZip(t, map[string]string{"manifest.json": "{}"})
	if err := extractZipInto(zipPath, t.TempDir(), "overrides", false); err != nil {
		t.Fatalf("missing overrides dir should not error: %v", err)
	}
}

func TestExtractZipIntoServerPackWrapper(t *testing.T) {
	zipPath := buildZip(t, map[string]string{
		"ServerFiles-1.2.3/mods/a.jar":        "a",
		"ServerFiles-1.2.3/config/b.toml":     "b",
		"ServerFiles-1.2.3/server.properties": "c",
	})

	serverDir := t.TempDir()
	if err := extractZipInto(zipPath, serverDir, "", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"mods/a.jar", "config/b.toml", "server.properties"} {
		if _, err := os.Stat(filepath.Join(serverDir, want)); err != nil {
			t.Errorf("expected wrapper-stripped %s: %v", want, err)
		}
	}
}

func TestExtractZipIntoServerPackNoWrapper(t *testing.T) {
	zipPath := buildZip(t, map[string]string{
		"mods/a.jar":        "a",
		"config/b.toml":     "b",
		"server.properties": "c",
	})

	serverDir := t.TempDir()
	if err := extractZipInto(zipPath, serverDir, "", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(serverDir, "mods", "a.jar")); err != nil {
		t.Errorf("root-level pack extracted wrong: %v", err)
	}
}

func TestExtractZipIntoModsOnlyPackNotStripped(t *testing.T) {
	// A pack whose only top-level dir is a standard server dir must NOT have
	// that dir stripped (jars would land in the server root).
	zipPath := buildZip(t, map[string]string{
		"mods/a.jar": "a",
		"mods/b.jar": "b",
	})

	serverDir := t.TempDir()
	if err := extractZipInto(zipPath, serverDir, "", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(serverDir, "mods", "a.jar")); err != nil {
		t.Errorf("mods/ was incorrectly stripped: %v", err)
	}
}

func TestExtractZipIntoRejectsZipSlip(t *testing.T) {
	// Hand-build a zip containing a traversal entry; zip.Writer.Create
	// allows arbitrary names.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fw, err := w.Create("../evil.jar")
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte("evil"))
	w.Close()
	zipPath := filepath.Join(t.TempDir(), "evil.zip")
	if err := os.WriteFile(zipPath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	base := t.TempDir()
	serverDir := filepath.Join(base, "server")
	if err := os.MkdirAll(serverDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := extractZipInto(zipPath, serverDir, "", false); err == nil {
		t.Fatal("zip-slip entry not rejected")
	}
	if _, err := os.Stat(filepath.Join(base, "evil.jar")); !os.IsNotExist(err) {
		t.Error("zip-slip file escaped the server dir")
	}
}

func TestDownloadAndExtractZip(t *testing.T) {
	zipPath := buildZip(t, map[string]string{
		"overrides/config/x.toml": "x",
	})
	zipBytes, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(zipBytes)
	}))
	defer ts.Close()

	serverDir := t.TempDir()
	client := &http.Client{Timeout: 5 * time.Second}
	if err := downloadAndExtractZip(client, ts.URL+"/pack.zip", serverDir, "overrides", false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(serverDir, "config", "x.toml")); err != nil {
		t.Errorf("expected extracted override: %v", err)
	}
}

func TestDetectWrapperDir(t *testing.T) {
	cases := []struct {
		name    string
		entries map[string]string
		want    string
	}{
		{"wrapper", map[string]string{"Pack-1.0/mods/a.jar": "a", "Pack-1.0/x.txt": "x"}, "Pack-1.0/"},
		{"root files", map[string]string{"a.txt": "a", "Pack/x.txt": "x"}, ""},
		{"multiple tops", map[string]string{"a/x.txt": "x", "b/y.txt": "y"}, ""},
		{"standard dir", map[string]string{"mods/a.jar": "a"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zipPath := buildZip(t, tc.entries)
			r, err := zip.OpenReader(zipPath)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if got := detectWrapperDir(r.File); got != tc.want {
				t.Errorf("detectWrapperDir = %q, want %q", got, tc.want)
			}
		})
	}
}
