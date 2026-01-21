package handlers

import (
	"github.com/go-chi/chi/v5"
)

// RegisterRoutes registers all Hytale-specific routes under the given router
// Expected to be mounted at /api/servers/{uuid}/hytale
func (h *HytaleHandlers) RegisterRoutes(r chi.Router) {
	// Mod operations
	r.Route("/mods", func(r chi.Router) {
		r.Get("/", h.ListMods)
		r.Post("/download", h.DownloadMod)
		r.Delete("/", h.DeleteMod)
		r.Post("/toggle", h.ToggleMod)
		r.Post("/backup", h.BackupMod)
		r.Post("/restore", h.RestoreMod)
	})
}
