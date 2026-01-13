package handlers

import (
	"github.com/go-chi/chi/v5"
)

// RegisterRoutes registers all Minecraft-specific routes under the given router
// Expected to be mounted at /api/servers/{uuid}/minecraft
func (h *MinecraftHandlers) RegisterRoutes(r chi.Router) {
	// Gamerules (Management Protocol 1.21.9+)
	r.Get("/gamerules", h.GetGamerules)
	r.Post("/gamerules", h.UpdateGamerule)
	r.Get("/discover", h.DiscoverSchema) // Debug: RPC schema

	// Server properties
	r.Get("/properties", h.GetProperties)
	r.Get("/properties/info", h.GetPropertiesWithInfo)
	r.Get("/world-info", h.GetWorldInfo)

	// Datapack operations
	r.Route("/datapacks", func(r chi.Router) {
		r.Get("/", h.ListDatapacks)
		r.Post("/download", h.DownloadDatapack)
		r.Delete("/", h.DeleteDatapack)
	})

	// Mod/Plugin operations
	r.Route("/mods", func(r chi.Router) {
		r.Get("/", h.ListMods)
		r.Post("/download", h.DownloadMod)
		r.Delete("/", h.DeleteMod)
		r.Post("/toggle", h.ToggleMod)
		r.Post("/backup", h.BackupMod)
		r.Post("/restore", h.RestoreMod)
	})

	// Player management
	r.Route("/players", func(r chi.Router) {
		r.Get("/list", h.ListPlayers)
		r.Post("/kick", h.KickPlayer)
		r.Post("/ban", h.BanPlayer)
		r.Post("/pardon", h.PardonPlayer)
		r.Get("/banlist", h.GetBanList)
		r.Get("/whitelist", h.GetWhitelist)
		r.Post("/whitelist", h.ModifyWhitelist)
		r.Get("/whitelist/status", h.GetWhitelistStatus)
		r.Post("/whitelist/enable", h.SetWhitelistEnabled)
		r.Post("/whitelist/enforce", h.SetWhitelistEnforced)
		r.Get("/ops", h.GetOps)
		r.Post("/op", h.OpPlayer)
		r.Post("/deop", h.DeopPlayer)
		r.Get("/ip-banlist", h.GetIPBanList)
		r.Post("/ban-ip", h.BanIP)
		r.Post("/pardon-ip", h.PardonIP)
	})

	// RCON operations
	r.Post("/rcon", h.RawRCONCommand)
	r.Post("/rcon/configure", h.ConfigureRCON)

	// Management Protocol configuration (1.21.9+)
	r.Post("/management/configure", h.ConfigureManagement)

	// Broadcast messages
	r.Post("/broadcast", h.BroadcastMessage)
}
