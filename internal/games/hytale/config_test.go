package hytale

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSyncServerConfigUpdatesMaxPlayers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	original := `{"Version": 3, "ServerName": "My Server", "MaxPlayers": 100, "MaxViewRadius": 32, "Defaults": {"World": "default"}}`
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	if err := SyncServerConfig(dir, map[string]string{"MAX_PLAYERS": "20"}); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if config["MaxPlayers"] != float64(20) {
		t.Errorf("MaxPlayers = %v, want 20", config["MaxPlayers"])
	}
	if config["ServerName"] != "My Server" || config["MaxViewRadius"] != float64(32) || config["Defaults"] == nil {
		t.Errorf("other keys were not preserved: %s", data)
	}
}

func TestSyncServerConfigSkipsMissingConfig(t *testing.T) {
	dir := t.TempDir()
	if err := SyncServerConfig(dir, map[string]string{"MAX_PLAYERS": "20"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); !os.IsNotExist(err) {
		t.Error("config.json should not be created")
	}
}

func TestSyncServerConfigRejectsInvalidValue(t *testing.T) {
	if err := SyncServerConfig(t.TempDir(), map[string]string{"MAX_PLAYERS": "lots"}); err == nil {
		t.Error("expected an error for a non-numeric MAX_PLAYERS")
	}
}
