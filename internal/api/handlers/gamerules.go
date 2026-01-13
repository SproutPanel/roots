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

// DiscoverSchema handles GET /api/servers/{uuid}/discover
// Returns the RPC schema for debugging
func (sm *ServerManager) DiscoverSchema(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	mgmtClient, err := sm.getPersistentManagementClient(uuid)
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

// GetGamerules handles GET /api/servers/{uuid}/gamerules
// Returns all gamerules with their current values (requires Management Protocol 1.21.9+)
func (sm *ServerManager) GetGamerules(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	sm.mu.RLock()
	server, ok := sm.servers[uuid]
	sm.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	if server.Status != "online" {
		http.Error(w, "Server must be online to query gamerules", http.StatusConflict)
		return
	}

	// Gamerules require Management Protocol (1.21.9+)
	mgmtClient, err := sm.getPersistentManagementClient(uuid)
	if err != nil {
		http.Error(w, "Management Protocol not available: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	gamerules, err := mgmtClient.QueryGamerules()
	if err != nil {
		sm.logger.Error("Failed to query gamerules", "error", err)
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

// UpdateGamerule handles POST /api/servers/{uuid}/gamerules
// Updates a single gamerule value (requires Management Protocol 1.21.9+)
func (sm *ServerManager) UpdateGamerule(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	sm.mu.RLock()
	server, ok := sm.servers[uuid]
	sm.mu.RUnlock()

	if !ok {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	if server.Status != "online" {
		http.Error(w, "Server must be online to update gamerules", http.StatusConflict)
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
	if mgmtClient, err := sm.getPersistentManagementClient(uuid); err == nil {
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
		sm.logger.Warn("Management Protocol gamerule update failed, falling back to RCON", "error", err)
	}

	// Fall back to RCON /gamerule command
	client, err := sm.getPersistentRCONClient(uuid)
	if err != nil {
		http.Error(w, "Failed to connect to RCON: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	// RCON expects plain gamerule names without minecraft: prefix
	rconKey := strings.TrimPrefix(req.Key, "minecraft:")

	result, err := client.Execute("gamerule " + rconKey + " " + req.Value)
	if err != nil {
		sm.closeRCONConnection(uuid)
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

// GetGameruleInfo returns category information for organizing gamerules in UI
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
