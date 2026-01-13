package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/sproutpanel/roots/internal/games/minecraft"
)

// PlayerActionRequest represents a request to perform an action on a player
type PlayerActionRequest struct {
	Player string `json:"player"`
	Reason string `json:"reason,omitempty"`
}

// WhitelistActionRequest represents a whitelist modification request
type WhitelistActionRequest struct {
	Action string `json:"action"` // "add" or "remove"
	Player string `json:"player"`
}

// OpEntry represents an entry in ops.json
type OpEntry struct {
	UUID                string `json:"uuid"`
	Name                string `json:"name"`
	Level               int    `json:"level"`
	BypassesPlayerLimit bool   `json:"bypassesPlayerLimit"`
}

// WhitelistEntry represents an entry in whitelist.json
type WhitelistEntry struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

// BannedPlayerEntry represents an entry in banned-players.json
type BannedPlayerEntry struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Created string `json:"created"`
	Source  string `json:"source"`
	Expires string `json:"expires"`
	Reason  string `json:"reason"`
}

// IPBanEntry represents an entry in banned-ips.json
type IPBanEntry struct {
	IP      string `json:"ip"`
	Created string `json:"created"`
	Source  string `json:"source"`
	Expires string `json:"expires"`
	Reason  string `json:"reason"`
}

// IPBanRequest represents a request to ban an IP
type IPBanRequest struct {
	IP     string `json:"ip"`
	Reason string `json:"reason,omitempty"`
}

// ListPlayersResponse is the response for listing online players
type ListPlayersResponse struct {
	Online  int                    `json:"online"`
	Max     int                    `json:"max"`
	Players []minecraft.PlayerInfo `json:"players"`
}

// TextSegment represents a single segment of formatted text
type TextSegment struct {
	Text          string `json:"text"`
	Color         string `json:"color,omitempty"`
	Bold          bool   `json:"bold,omitempty"`
	Italic        bool   `json:"italic,omitempty"`
	Underlined    bool   `json:"underlined,omitempty"`
	Strikethrough bool   `json:"strikethrough,omitempty"`
}

// BroadcastRequest represents a request to broadcast a message
type BroadcastRequest struct {
	// Simple mode - single message with optional formatting
	Message       string `json:"message,omitempty"`
	Color         string `json:"color,omitempty"`
	Bold          bool   `json:"bold,omitempty"`
	Italic        bool   `json:"italic,omitempty"`
	Underlined    bool   `json:"underlined,omitempty"`
	Strikethrough bool   `json:"strikethrough,omitempty"`

	// Advanced mode - multiple segments with individual formatting
	Segments []TextSegment `json:"segments,omitempty"`

	// Common options
	Overlay bool     `json:"overlay,omitempty"` // If true, shows as action bar
	Players []string `json:"players,omitempty"` // If empty, sends to all
}

// ListPlayers handles GET /api/servers/{uuid}/minecraft/players/list
// Tries Management Protocol (1.21.9+) first, then falls back to RCON
func (h *MinecraftHandlers) ListPlayers(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	server, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	// Check if server is running
	if server.Status != "online" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ListPlayersResponse{
			Online:  0,
			Max:     0,
			Players: []minecraft.PlayerInfo{},
		})
		return
	}

	// Try Management Protocol first (1.21.9+) - provides full player list with UUIDs
	if mgmtClient, err := h.provider.GetManagementClient(uuid); err == nil {
		if players, err := mgmtClient.QueryPlayers(); err == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ListPlayersResponse{
				Online:  len(players),
				Max:     20, // TODO: get from server settings
				Players: players,
			})
			return
		}
	}

	// Fall back to RCON
	client, err := h.provider.GetRCONClient(uuid)
	if err != nil {
		h.logger.Error("Failed to create RCON client", "error", err)
		http.Error(w, "Failed to connect to RCON: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	playersResp, err := client.ListPlayers()
	if err != nil {
		// Connection may be stale, close it so it reconnects next time
		h.provider.CloseRCONConnection(uuid)
		h.logger.Error("Failed to list players", "error", err)
		http.Error(w, "Failed to list players: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(playersResp)
}

// KickPlayer handles POST /api/servers/{uuid}/minecraft/players/kick
// Tries Management Protocol (1.21.9+) first, then falls back to RCON
func (h *MinecraftHandlers) KickPlayer(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	var req PlayerActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Player == "" {
		http.Error(w, "Player name is required", http.StatusBadRequest)
		return
	}

	// Try Management Protocol first (1.21.9+)
	if mgmtClient, err := h.provider.GetManagementClient(uuid); err == nil {
		if err := mgmtClient.KickPlayer(req.Player, req.Reason); err == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"result": req.Player + " has been kicked"})
			return
		}
	}

	// Fall back to RCON
	client, err := h.provider.GetRCONClient(uuid)
	if err != nil {
		http.Error(w, "Failed to connect to RCON: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	result, err := client.Kick(req.Player, req.Reason)
	if err != nil {
		h.provider.CloseRCONConnection(uuid)
		http.Error(w, "Failed to kick player: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"result": result})
}

// BanPlayer handles POST /api/servers/{uuid}/minecraft/players/ban
// Tries Management Protocol (1.21.9+) first, then falls back to RCON
func (h *MinecraftHandlers) BanPlayer(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	var req PlayerActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Player == "" {
		http.Error(w, "Player name is required", http.StatusBadRequest)
		return
	}

	// Try Management Protocol first (1.21.9+)
	if mgmtClient, err := h.provider.GetManagementClient(uuid); err == nil {
		if err := mgmtClient.BanPlayer(req.Player, req.Reason); err == nil {
			// Also kick the player so they see the ban reason
			kickReason := "Banned"
			if req.Reason != "" {
				kickReason = "Banned: " + req.Reason
			}
			mgmtClient.KickPlayer(req.Player, kickReason) // Ignore error - player may already be offline

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"result": req.Player + " has been banned"})
			return
		}
	}

	// Fall back to RCON - ban command already kicks the player with reason
	client, err := h.provider.GetRCONClient(uuid)
	if err != nil {
		http.Error(w, "Failed to connect to RCON: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	result, err := client.Ban(req.Player, req.Reason)
	if err != nil {
		h.provider.CloseRCONConnection(uuid)
		http.Error(w, "Failed to ban player: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"result": result})
}

// PardonPlayer handles POST /api/servers/{uuid}/minecraft/players/pardon
// Tries Management Protocol (1.21.9+) first, then falls back to RCON
func (h *MinecraftHandlers) PardonPlayer(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	var req PlayerActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Player == "" {
		http.Error(w, "Player name is required", http.StatusBadRequest)
		return
	}

	// Try Management Protocol first (1.21.9+)
	if mgmtClient, err := h.provider.GetManagementClient(uuid); err == nil {
		if err := mgmtClient.UnbanPlayer(req.Player); err == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"result": req.Player + " has been pardoned"})
			return
		}
	}

	// Fall back to RCON
	client, err := h.provider.GetRCONClient(uuid)
	if err != nil {
		http.Error(w, "Failed to connect to RCON: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	result, err := client.Pardon(req.Player)
	if err != nil {
		h.provider.CloseRCONConnection(uuid)
		http.Error(w, "Failed to pardon player: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"result": result})
}

// GetBanList handles GET /api/servers/{uuid}/minecraft/players/banlist
// Reads banned-players.json for detailed ban info
func (h *MinecraftHandlers) GetBanList(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	serverDir := h.provider.GetServerDir(uuid)
	banListPath := filepath.Join(serverDir, "banned-players.json")

	bans, err := parseBannedPlayersFile(banListPath)
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]BannedPlayerEntry{})
			return
		}
		http.Error(w, "Failed to read ban list: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bans)
}

// GetWhitelist handles GET /api/servers/{uuid}/minecraft/players/whitelist
// Reads whitelist.json
func (h *MinecraftHandlers) GetWhitelist(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	serverDir := h.provider.GetServerDir(uuid)
	whitelistPath := filepath.Join(serverDir, "whitelist.json")

	whitelist, err := parseWhitelistFile(whitelistPath)
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]WhitelistEntry{})
			return
		}
		http.Error(w, "Failed to read whitelist: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(whitelist)
}

// ModifyWhitelist handles POST /api/servers/{uuid}/minecraft/players/whitelist
// Tries Management Protocol (1.21.9+) first, then falls back to RCON
func (h *MinecraftHandlers) ModifyWhitelist(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	var req WhitelistActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Player == "" {
		http.Error(w, "Player name is required", http.StatusBadRequest)
		return
	}

	if req.Action != "add" && req.Action != "remove" {
		http.Error(w, "Action must be 'add' or 'remove'", http.StatusBadRequest)
		return
	}

	// Try Management Protocol first (1.21.9+) - uses "allowlist" terminology
	if mgmtClient, err := h.provider.GetManagementClient(uuid); err == nil {
		var mgmtErr error
		if req.Action == "add" {
			mgmtErr = mgmtClient.AddToAllowlist(req.Player)
		} else {
			mgmtErr = mgmtClient.RemoveFromAllowlist(req.Player)
		}

		if mgmtErr == nil {
			result := req.Player + " added to whitelist"
			if req.Action == "remove" {
				result = req.Player + " removed from whitelist"
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"result": result})
			return
		}
	}

	// Fall back to RCON
	client, err := h.provider.GetRCONClient(uuid)
	if err != nil {
		http.Error(w, "Failed to connect to RCON: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	var result string
	if req.Action == "add" {
		result, err = client.WhitelistAdd(req.Player)
	} else {
		result, err = client.WhitelistRemove(req.Player)
	}

	if err != nil {
		h.provider.CloseRCONConnection(uuid)
		http.Error(w, "Failed to modify whitelist: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"result": result})
}

// GetWhitelistStatus handles GET /api/servers/{uuid}/minecraft/players/whitelist/status
// Returns whether the whitelist is enabled and enforced on the server
func (h *MinecraftHandlers) GetWhitelistStatus(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	server, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	// Try Management Protocol first (1.21.9+)
	if server.Status == "online" {
		if mgmtClient, err := h.provider.GetManagementClient(uuid); err == nil {
			enabled, enabledErr := mgmtClient.IsAllowlistEnabled()
			enforced, enforcedErr := mgmtClient.IsAllowlistEnforced()
			if enabledErr == nil {
				response := map[string]interface{}{
					"enabled": enabled,
					"source":  "management",
				}
				if enforcedErr == nil {
					response["enforced"] = enforced
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
				return
			}
		}
	}

	// Fall back to reading server.properties
	serverDir := h.provider.GetServerDir(uuid)
	propsPath := filepath.Join(serverDir, "server.properties")

	props, err := parsePropertiesFile(propsPath)
	if err != nil {
		// If we can't read properties, assume disabled
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled":  false,
			"enforced": false,
			"source":   "unknown",
		})
		return
	}

	enabled := props["white-list"] == "true"
	enforced := props["enforce-whitelist"] == "true"
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":  enabled,
		"enforced": enforced,
		"source":   "properties",
	})
}

// SetWhitelistEnabled handles POST /api/servers/{uuid}/minecraft/players/whitelist/enable
// Enables or disables the whitelist on the server
func (h *MinecraftHandlers) SetWhitelistEnabled(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Try Management Protocol first (1.21.9+)
	if mgmtClient, err := h.provider.GetManagementClient(uuid); err == nil {
		err := mgmtClient.SetAllowlistEnabled(req.Enabled)
		if err == nil {
			action := "disabled"
			if req.Enabled {
				action = "enabled"
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"result": "Whitelist " + action,
			})
			return
		}
	}

	// Fall back to RCON
	client, err := h.provider.GetRCONClient(uuid)
	if err != nil {
		http.Error(w, "Failed to connect: "+err.Error(), http.StatusInternalServerError)
		return
	}

	command := "whitelist off"
	if req.Enabled {
		command = "whitelist on"
	}

	result, err := client.Execute(command)
	if err != nil {
		h.provider.CloseRCONConnection(uuid)
		http.Error(w, "Failed to execute command: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"result": result})
}

// SetWhitelistEnforced handles POST /api/servers/{uuid}/minecraft/players/whitelist/enforce
// Enables or disables whitelist enforcement (kicks players immediately on removal)
func (h *MinecraftHandlers) SetWhitelistEnforced(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	var req struct {
		Enforced bool `json:"enforced"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Management Protocol only (1.21.9+) - no RCON fallback for this setting
	mgmtClient, err := h.provider.GetManagementClient(uuid)
	if err != nil {
		http.Error(w, "Management Protocol not available: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	err = mgmtClient.SetAllowlistEnforced(req.Enforced)
	if err != nil {
		http.Error(w, "Failed to set enforce whitelist: "+err.Error(), http.StatusInternalServerError)
		return
	}

	action := "disabled"
	if req.Enforced {
		action = "enabled"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"result": "Whitelist enforcement " + action,
	})
}

// GetOps handles GET /api/servers/{uuid}/minecraft/players/ops
// Reads ops.json since there's no RCON command to list ops
func (h *MinecraftHandlers) GetOps(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	serverDir := h.provider.GetServerDir(uuid)
	opsPath := filepath.Join(serverDir, "ops.json")

	ops, err := parseOpsFile(opsPath)
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]OpEntry{})
			return
		}
		http.Error(w, "Failed to read ops: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ops)
}

// OpPlayer handles POST /api/servers/{uuid}/minecraft/players/op
// Tries Management Protocol (1.21.9+) first, then falls back to RCON
func (h *MinecraftHandlers) OpPlayer(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	var req PlayerActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Player == "" {
		http.Error(w, "Player name is required", http.StatusBadRequest)
		return
	}

	// Try Management Protocol first (1.21.9+)
	if mgmtClient, err := h.provider.GetManagementClient(uuid); err == nil {
		// Default to level 4 (full operator)
		if err := mgmtClient.AddOperator(req.Player, 4); err == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"result": req.Player + " is now an operator"})
			return
		}
	}

	// Fall back to RCON
	client, err := h.provider.GetRCONClient(uuid)
	if err != nil {
		http.Error(w, "Failed to connect to RCON: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	result, err := client.Op(req.Player)
	if err != nil {
		h.provider.CloseRCONConnection(uuid)
		http.Error(w, "Failed to op player: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"result": result})
}

// DeopPlayer handles POST /api/servers/{uuid}/minecraft/players/deop
// Tries Management Protocol (1.21.9+) first, then falls back to RCON
func (h *MinecraftHandlers) DeopPlayer(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	var req PlayerActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Player == "" {
		http.Error(w, "Player name is required", http.StatusBadRequest)
		return
	}

	// Try Management Protocol first (1.21.9+)
	if mgmtClient, err := h.provider.GetManagementClient(uuid); err == nil {
		if err := mgmtClient.RemoveOperator(req.Player); err == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"result": req.Player + " is no longer an operator"})
			return
		}
	}

	// Fall back to RCON
	client, err := h.provider.GetRCONClient(uuid)
	if err != nil {
		http.Error(w, "Failed to connect to RCON: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	result, err := client.Deop(req.Player)
	if err != nil {
		h.provider.CloseRCONConnection(uuid)
		http.Error(w, "Failed to deop player: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"result": result})
}

// GetIPBanList handles GET /api/servers/{uuid}/minecraft/players/ip-banlist
func (h *MinecraftHandlers) GetIPBanList(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	server, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	// Try Management Protocol first (1.21.9+)
	if server.Status == "online" {
		if mgmtClient, err := h.provider.GetManagementClient(uuid); err == nil {
			if bans, err := mgmtClient.QueryIPBans(); err == nil {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(bans)
				return
			}
		}
	}

	// Fall back to reading banned-ips.json
	serverDir := h.provider.GetServerDir(uuid)
	banListPath := filepath.Join(serverDir, "banned-ips.json")

	bans, err := parseIPBanFile(banListPath)
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]IPBanEntry{})
			return
		}
		http.Error(w, "Failed to read IP ban list: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bans)
}

// BanIP handles POST /api/servers/{uuid}/minecraft/players/ban-ip
func (h *MinecraftHandlers) BanIP(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	var req IPBanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.IP == "" {
		http.Error(w, "IP address is required", http.StatusBadRequest)
		return
	}

	// Try Management Protocol first (1.21.9+)
	if mgmtClient, err := h.provider.GetManagementClient(uuid); err == nil {
		if err := mgmtClient.BanIP(req.IP, req.Reason); err == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"result": req.IP + " has been banned"})
			return
		}
	}

	// Fall back to RCON
	client, err := h.provider.GetRCONClient(uuid)
	if err != nil {
		http.Error(w, "Failed to connect to RCON: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	cmd := "ban-ip " + req.IP
	if req.Reason != "" {
		cmd += " " + req.Reason
	}
	result, err := client.Execute(cmd)
	if err != nil {
		h.provider.CloseRCONConnection(uuid)
		http.Error(w, "Failed to ban IP: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"result": result})
}

// PardonIP handles POST /api/servers/{uuid}/minecraft/players/pardon-ip
func (h *MinecraftHandlers) PardonIP(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	var req IPBanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.IP == "" {
		http.Error(w, "IP address is required", http.StatusBadRequest)
		return
	}

	// Try Management Protocol first (1.21.9+)
	if mgmtClient, err := h.provider.GetManagementClient(uuid); err == nil {
		if err := mgmtClient.UnbanIP(req.IP); err == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"result": req.IP + " has been pardoned"})
			return
		}
	}

	// Fall back to RCON
	client, err := h.provider.GetRCONClient(uuid)
	if err != nil {
		http.Error(w, "Failed to connect to RCON: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	result, err := client.Execute("pardon-ip " + req.IP)
	if err != nil {
		h.provider.CloseRCONConnection(uuid)
		http.Error(w, "Failed to pardon IP: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"result": result})
}

// RawRCONCommand handles POST /api/servers/{uuid}/minecraft/rcon
// Executes an arbitrary RCON command (for advanced users)
func (h *MinecraftHandlers) RawRCONCommand(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	var req struct {
		Command string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Command == "" {
		http.Error(w, "Command is required", http.StatusBadRequest)
		return
	}

	client, err := h.provider.GetRCONClient(uuid)
	if err != nil {
		http.Error(w, "Failed to connect to RCON: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	result, err := client.Execute(req.Command)
	if err != nil {
		h.provider.CloseRCONConnection(uuid)
		http.Error(w, "Failed to execute command: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"result": result})
}

// ConfigureRCON handles POST /api/servers/{uuid}/minecraft/rcon/configure
// Enables RCON in server.properties for existing servers
func (h *MinecraftHandlers) ConfigureRCON(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	server, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	// Server must be stopped to modify server.properties
	if server.Status == "online" || server.Status == "starting" {
		http.Error(w, "Server must be stopped to configure RCON", http.StatusConflict)
		return
	}

	serverDir := h.provider.GetServerDir(uuid)

	// Configure RCON with auto-generated password
	rconCfg, err := minecraft.ConfigureRCON(serverDir, 25575, "")
	if err != nil {
		h.logger.Error("Failed to configure RCON", "uuid", uuid, "error", err)
		http.Error(w, "Failed to configure RCON: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.logger.Info("Configured RCON for existing server", "uuid", uuid, "port", rconCfg.Port)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"configured": true,
		"port":       rconCfg.Port,
		"message":    "RCON configured. Restart the server to apply changes.",
	})
}

// ConfigureManagement handles POST /api/servers/{uuid}/minecraft/management/configure
// Enables Management Protocol in server.properties for existing servers (1.21.9+)
func (h *MinecraftHandlers) ConfigureManagement(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	server, err := h.requireMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	// Server must be stopped to modify server.properties
	if server.Status == "online" || server.Status == "starting" {
		http.Error(w, "Server must be stopped to configure Management Protocol", http.StatusConflict)
		return
	}

	serverDir := h.provider.GetServerDir(uuid)

	// Configure Management Protocol with auto-generated secret
	mgmtCfg, err := minecraft.ConfigureManagement(serverDir, 25576, "")
	if err != nil {
		h.logger.Error("Failed to configure Management Protocol", "uuid", uuid, "error", err)
		http.Error(w, "Failed to configure Management Protocol: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.logger.Info("Configured Management Protocol for existing server", "uuid", uuid, "port", mgmtCfg.Port)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"configured": true,
		"port":       mgmtCfg.Port,
		"message":    "Management Protocol configured. Restart the server to apply changes.",
	})
}

// BroadcastMessage handles POST /api/servers/{uuid}/minecraft/broadcast
func (h *MinecraftHandlers) BroadcastMessage(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireOnlineMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	var req BroadcastRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Determine if using segments mode or simple mode
	useSegments := len(req.Segments) > 0

	if !useSegments && req.Message == "" {
		http.Error(w, "Message or segments required", http.StatusBadRequest)
		return
	}

	// Check if any formatting is present
	hasFormatting := false
	if useSegments {
		// Segments always need tellraw (multiple components)
		hasFormatting = true
	} else {
		// Simple mode - check if formatting is requested
		textComponent := minecraft.TextComponent{
			Text:          req.Message,
			Color:         req.Color,
			Bold:          req.Bold,
			Italic:        req.Italic,
			Underlined:    req.Underlined,
			Strikethrough: req.Strikethrough,
		}
		hasFormatting = textComponent.HasFormatting()
	}

	// If NO formatting requested (simple plain text), use Management Protocol
	if !hasFormatting {
		if mgmtClient, err := h.provider.GetManagementClient(uuid); err == nil {
			if err := mgmtClient.SendPlainSystemMessage(req.Message, req.Overlay, req.Players); err == nil {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"sent":    true,
					"message": req.Message,
				})
				return
			}
		}
	}

	// Formatting requested OR Management Protocol not available - use RCON /tellraw
	client, err := h.provider.GetRCONClient(uuid)
	if err != nil {
		http.Error(w, "Failed to connect to RCON: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Build JSON text component(s) for tellraw
	var jsonMsg []byte

	if useSegments {
		// Build array of text components: ["", {segment1}, {segment2}, ...]
		// The empty string is the base component required by tellraw
		components := make([]interface{}, 0, len(req.Segments)+1)
		components = append(components, "") // Base component

		for _, seg := range req.Segments {
			if seg.Text == "" {
				continue
			}
			component := map[string]interface{}{
				"text": seg.Text,
			}
			if seg.Color != "" {
				component["color"] = seg.Color
			}
			if seg.Bold {
				component["bold"] = true
			}
			if seg.Italic {
				component["italic"] = true
			}
			if seg.Underlined {
				component["underlined"] = true
			}
			if seg.Strikethrough {
				component["strikethrough"] = true
			}
			components = append(components, component)
		}
		jsonMsg, _ = json.Marshal(components)
	} else {
		// Simple mode - single component
		component := map[string]interface{}{
			"text": req.Message,
		}
		if req.Color != "" {
			component["color"] = req.Color
		}
		if req.Bold {
			component["bold"] = true
		}
		if req.Italic {
			component["italic"] = true
		}
		if req.Underlined {
			component["underlined"] = true
		}
		if req.Strikethrough {
			component["strikethrough"] = true
		}
		jsonMsg, _ = json.Marshal(component)
	}

	var cmd string
	if req.Overlay {
		// Use title actionbar for overlay
		cmd = fmt.Sprintf("title @a actionbar %s", string(jsonMsg))
	} else {
		cmd = fmt.Sprintf("tellraw @a %s", string(jsonMsg))
	}

	result, err := client.Execute(cmd)
	if err != nil {
		h.provider.CloseRCONConnection(uuid)
		http.Error(w, "Failed to broadcast message: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sent":   true,
		"result": result,
	})
}

// Helper functions for parsing Minecraft JSON files

func parseOpsFile(path string) ([]OpEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ops []OpEntry
	if err := json.Unmarshal(data, &ops); err != nil {
		return nil, err
	}

	return ops, nil
}

func parseWhitelistFile(path string) ([]WhitelistEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var whitelist []WhitelistEntry
	if err := json.Unmarshal(data, &whitelist); err != nil {
		return nil, err
	}

	return whitelist, nil
}

func parseBannedPlayersFile(path string) ([]BannedPlayerEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var bans []BannedPlayerEntry
	if err := json.Unmarshal(data, &bans); err != nil {
		return nil, err
	}

	return bans, nil
}

func parseIPBanFile(path string) ([]IPBanEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var bans []IPBanEntry
	if err := json.Unmarshal(data, &bans); err != nil {
		return nil, err
	}

	return bans, nil
}
