package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// GameruleResponse represents a gamerule in the API response
type GameruleResponse struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
	Type  string      `json:"type"` // "boolean" or "integer"
}

// UpdateGameruleRequest represents a request to update a gamerule
type UpdateGameruleRequest struct {
	Key   string `json:"key"`
	Value string `json:"value"` // String representation of the value
}

// DiscoverSchema handles GET /api/servers/{uuid}/minecraft/discover
// Returns the RPC schema for debugging
func (h *MinecraftHandlers) DiscoverSchema(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireOnlineMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	mgmtClient, err := h.provider.GetManagementClient(uuid)
	if err != nil {
		http.Error(w, "Management Protocol not available: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	schema, err := mgmtClient.Discover()
	if err != nil {
		http.Error(w, "Failed to discover schema: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(schema)
}

// GetGamerules handles GET /api/servers/{uuid}/minecraft/gamerules
// Returns all gamerules with their current values (requires Management Protocol 1.21.9+)
func (h *MinecraftHandlers) GetGamerules(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireOnlineMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	// Gamerules require Management Protocol (1.21.9+)
	mgmtClient, err := h.provider.GetManagementClient(uuid)
	if err != nil {
		http.Error(w, "Management Protocol not available: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	gamerules, err := mgmtClient.QueryGamerules()
	if err != nil {
		h.logger.Error("Failed to query gamerules", "error", err)
		http.Error(w, "Failed to query gamerules: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert to response format
	response := make([]GameruleResponse, len(gamerules))
	for i, gr := range gamerules {
		response[i] = GameruleResponse{
			Key:   gr.Key,
			Value: gr.Value,
			Type:  gr.Type,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// UpdateGamerule handles POST /api/servers/{uuid}/minecraft/gamerules
// Updates a single gamerule value (requires Management Protocol 1.21.9+ or falls back to RCON)
func (h *MinecraftHandlers) UpdateGamerule(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	_, err := h.requireOnlineMinecraftServer(r.Context(), uuid)
	if err != nil {
		h.writeError(w, err)
		return
	}

	var req UpdateGameruleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Key == "" {
		http.Error(w, "Gamerule key is required", http.StatusBadRequest)
		return
	}

	// Try Management Protocol first (1.21.9+)
	if mgmtClient, err := h.provider.GetManagementClient(uuid); err == nil {
		result, err := mgmtClient.UpdateGamerule(req.Key, req.Value)
		if err == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(GameruleResponse{
				Key:   result.Key,
				Value: result.Value,
				Type:  result.Type,
			})
			return
		}
		h.logger.Warn("Management Protocol gamerule update failed, falling back to RCON", "error", err)
	}

	// Fall back to RCON /gamerule command
	client, err := h.provider.GetRCONClient(uuid)
	if err != nil {
		http.Error(w, "Failed to connect to RCON: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	// RCON expects plain gamerule names without minecraft: prefix
	rconKey := strings.TrimPrefix(req.Key, "minecraft:")

	result, err := client.Execute("gamerule " + rconKey + " " + req.Value)
	if err != nil {
		h.provider.CloseRCONConnection(uuid)
		http.Error(w, "Failed to update gamerule: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"key":    req.Key,
		"value":  req.Value,
		"result": result,
	})
}

// writeError writes an appropriate HTTP error response for handler errors
func (h *MinecraftHandlers) writeError(w http.ResponseWriter, err error) {
	switch err {
	case ErrServerNotFound:
		http.Error(w, err.Error(), http.StatusNotFound)
	case ErrNotMinecraftServer:
		http.Error(w, err.Error(), http.StatusBadRequest)
	case ErrServerNotOnline:
		http.Error(w, err.Error(), http.StatusConflict)
	case ErrRCONNotAvailable, ErrManagementNotAvailable:
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// GameruleCategories for UI organization
var GameruleCategories = map[string][]string{
	"Player": {
		"keepInventory",
		"naturalRegeneration",
		"playersSleepingPercentage",
		"spawnRadius",
		"spectatorsGenerateChunks",
	},
	"Mobs": {
		"doMobSpawning",
		"doMobLoot",
		"mobGriefing",
		"doPatrolSpawning",
		"doTraderSpawning",
		"doWardenSpawning",
		"universalAnger",
		"forgiveDeadPlayers",
	},
	"Drops": {
		"doTileDrops",
		"doEntityDrops",
		"doMobLoot",
	},
	"World Updates": {
		"doDaylightCycle",
		"doWeatherCycle",
		"doFireTick",
		"randomTickSpeed",
		"doVinesSpread",
	},
	"Game Mechanics": {
		"doImmediateRespawn",
		"disableElytraMovementCheck",
		"disableRaids",
		"doInsomnia",
		"doLimitedCrafting",
		"projectilesCanBreakBlocks",
		"tntExplosionDropDecay",
		"blockExplosionDropDecay",
		"mobExplosionDropDecay",
	},
	"Commands & Chat": {
		"commandBlockOutput",
		"sendCommandFeedback",
		"logAdminCommands",
		"announceAdvancements",
		"showDeathMessages",
		"reducedDebugInfo",
	},
	"Technical": {
		"maxCommandChainLength",
		"maxCommandForkCount",
		"maxEntityCramming",
		"spawnChunkRadius",
		"commandModificationBlockLimit",
		"globalSoundEvents",
		"minecartMaxSpeed",
	},
}

// GetGameruleCategory returns category information for organizing gamerules in UI
func GetGameruleCategory(key string) string {
	for category, rules := range GameruleCategories {
		for _, rule := range rules {
			if rule == key {
				return category
			}
		}
	}
	return "Other"
}
