// Package hytale provides node-level Hytale services including OAuth2 authentication
// and the hytale-downloader integration.
package hytale

import (
	"log/slog"
	"sync"
	"time"

	"github.com/sproutpanel/roots/internal/config"
)

// CredentialStore manages Hytale OAuth2 credentials at the node level.
// These credentials are used by the hytale-downloader to download server files.
// Server-level authentication (for accepting player connections) is handled
// separately by each running Hytale server instance.
type CredentialStore struct {
	cfg        *config.Config
	configPath string
	logger     *slog.Logger
	mu         sync.RWMutex
}

// Credentials represents the OAuth2 credentials for Hytale
type Credentials struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// NewCredentialStore creates a new credential store
func NewCredentialStore(cfg *config.Config, configPath string, logger *slog.Logger) *CredentialStore {
	return &CredentialStore{
		cfg:        cfg,
		configPath: configPath,
		logger:     logger,
	}
}

// HasValidCredentials returns true if the node has valid Hytale OAuth credentials
func (cs *CredentialStore) HasValidCredentials() bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.cfg.Hytale.HasValidCredentials()
}

// NeedsRefresh returns true if the token should be refreshed soon
func (cs *CredentialStore) NeedsRefresh() bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.cfg.Hytale.NeedsRefresh()
}

// GetCredentials returns the current credentials
func (cs *CredentialStore) GetCredentials() *Credentials {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.cfg.Hytale.AccessToken == "" {
		return nil
	}

	return &Credentials{
		AccessToken:  cs.cfg.Hytale.AccessToken,
		RefreshToken: cs.cfg.Hytale.RefreshToken,
		ExpiresAt:    cs.cfg.Hytale.TokenExpiresAt,
	}
}

// SaveCredentials stores new OAuth credentials and persists to config file
func (cs *CredentialStore) SaveCredentials(accessToken, refreshToken string, expiresAt time.Time) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.cfg.Hytale.SetCredentials(accessToken, refreshToken, expiresAt)

	if err := cs.cfg.Save(cs.configPath); err != nil {
		cs.logger.Error("Failed to save Hytale credentials", "error", err)
		return err
	}

	cs.logger.Info("Hytale credentials saved successfully",
		"expires_at", expiresAt.Format(time.RFC3339))
	return nil
}

// ClearCredentials removes all OAuth credentials and persists to config file
func (cs *CredentialStore) ClearCredentials() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.cfg.Hytale.ClearCredentials()

	if err := cs.cfg.Save(cs.configPath); err != nil {
		cs.logger.Error("Failed to clear Hytale credentials", "error", err)
		return err
	}

	cs.logger.Info("Hytale credentials cleared")
	return nil
}

// GetAccessToken returns the current access token, or empty string if not authenticated
func (cs *CredentialStore) GetAccessToken() string {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.cfg.Hytale.AccessToken
}

// GetRefreshToken returns the current refresh token, or empty string if not authenticated
func (cs *CredentialStore) GetRefreshToken() string {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.cfg.Hytale.RefreshToken
}

// AuthStatus returns a summary of the current authentication status
type AuthStatus struct {
	Authenticated bool       `json:"authenticated"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	NeedsRefresh  bool       `json:"needs_refresh"`
}

// GetAuthStatus returns the current authentication status
func (cs *CredentialStore) GetAuthStatus() AuthStatus {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	status := AuthStatus{
		Authenticated: cs.cfg.Hytale.HasValidCredentials(),
		NeedsRefresh:  cs.cfg.Hytale.NeedsRefresh(),
	}

	if !cs.cfg.Hytale.TokenExpiresAt.IsZero() {
		status.ExpiresAt = &cs.cfg.Hytale.TokenExpiresAt
	}

	return status
}
