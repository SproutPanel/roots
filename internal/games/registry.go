package games

import (
	"log/slog"
	"sync"
)

// Registry manages game adapters
type Registry struct {
	adapters map[GameType]GameAdapter
	mu       sync.RWMutex
	logger   *slog.Logger
}

// NewRegistry creates a new adapter registry
func NewRegistry(logger *slog.Logger) *Registry {
	return &Registry{
		adapters: make(map[GameType]GameAdapter),
		logger:   logger,
	}
}

// Register adds a game adapter to the registry
func (r *Registry) Register(adapter GameAdapter) {
	r.mu.Lock()
	defer r.mu.Unlock()

	gameType := adapter.Type()
	r.adapters[gameType] = adapter
	r.logger.Info("Registered game adapter", "game", gameType)
}

// Get returns the adapter for a game type
func (r *Registry) Get(gameType GameType) (GameAdapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	adapter, ok := r.adapters[gameType]
	if !ok {
		return nil, ErrGameNotFound
	}
	return adapter, nil
}

// MustGet returns the adapter for a game type or panics
func (r *Registry) MustGet(gameType GameType) GameAdapter {
	adapter, err := r.Get(gameType)
	if err != nil {
		panic("game adapter not found: " + string(gameType))
	}
	return adapter
}

// Has checks if a game type is registered
func (r *Registry) Has(gameType GameType) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.adapters[gameType]
	return ok
}

// Types returns all registered game types
func (r *Registry) Types() []GameType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]GameType, 0, len(r.adapters))
	for t := range r.adapters {
		types = append(types, t)
	}
	return types
}

// DefaultRegistry is the global adapter registry
var DefaultRegistry *Registry

// InitDefaultRegistry initializes the default registry
func InitDefaultRegistry(logger *slog.Logger) {
	DefaultRegistry = NewRegistry(logger)
}

// GetAdapter returns the adapter for a game type from the default registry
func GetAdapter(gameType GameType) (GameAdapter, error) {
	if DefaultRegistry == nil {
		return nil, ErrGameNotFound
	}
	return DefaultRegistry.Get(gameType)
}
