package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sproutpanel/roots/internal/config"
)

// APIClient provides authenticated access to the roots daemon API
type APIClient struct {
	config     *config.Config
	httpClient *http.Client
	baseURL    string
	tlsEnabled bool
}

// NewAPIClient creates a new API client
func NewAPIClient() (*APIClient, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Build base URL with 0.0.0.0 -> 127.0.0.1 conversion
	host := cfg.Daemon.Host
	if host == "0.0.0.0" {
		host = "127.0.0.1"
	}

	// Determine protocol based on TLS config
	protocol := "http"
	tlsEnabled := cfg.TLSEnabled()
	if tlsEnabled {
		protocol = "https"
	}
	baseURL := fmt.Sprintf("%s://%s:%d", protocol, host, cfg.Daemon.Port)

	// Create HTTP client with TLS config
	httpClient := &http.Client{Timeout: 30 * time.Second}
	if tlsEnabled {
		// For local development/testing, allow self-signed certificates
		// In production, the daemon should use proper certificates
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				// Allow self-signed certs when connecting to localhost
				InsecureSkipVerify: isLocalhost(host),
			},
		}
	}

	return &APIClient{
		config:     cfg,
		httpClient: httpClient,
		baseURL:    baseURL,
		tlsEnabled: tlsEnabled,
	}, nil
}

// isLocalhost checks if the host is a localhost address
func isLocalhost(host string) bool {
	return host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "0.0.0.0"
}

// Config returns the loaded configuration
func (c *APIClient) Config() *config.Config {
	return c.config
}

// Get makes an authenticated GET request
func (c *APIClient) Get(path string) (*http.Response, error) {
	req, err := http.NewRequest("GET", c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.config.Panel.Token)
	return c.httpClient.Do(req)
}

// Post makes an authenticated POST request with JSON body
func (c *APIClient) Post(path string, body interface{}) (*http.Response, error) {
	var bodyReader *bytes.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(jsonBody)
	} else {
		bodyReader = bytes.NewReader([]byte{})
	}

	req, err := http.NewRequest("POST", c.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.config.Panel.Token)
	req.Header.Set("Content-Type", "application/json")
	return c.httpClient.Do(req)
}

// Delete makes an authenticated DELETE request
func (c *APIClient) Delete(path string) (*http.Response, error) {
	req, err := http.NewRequest("DELETE", c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.config.Panel.Token)
	return c.httpClient.Do(req)
}

// WebSocket connects to a WebSocket endpoint
func (c *APIClient) WebSocket(path string) (*websocket.Conn, error) {
	// Build WebSocket URL with appropriate protocol
	host := c.config.Daemon.Host
	if host == "0.0.0.0" {
		host = "127.0.0.1"
	}

	wsProtocol := "ws"
	if c.tlsEnabled {
		wsProtocol = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s:%d%s", wsProtocol, host, c.config.Daemon.Port, path)

	// Add token as query parameter for WebSocket auth
	u, err := url.Parse(wsURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("token", c.config.Panel.Token)
	u.RawQuery = q.Encode()

	// Create dialer with TLS config if needed
	dialer := websocket.DefaultDialer
	if c.tlsEnabled {
		dialer = &websocket.Dialer{
			TLSClientConfig: &tls.Config{
				// Allow self-signed certs when connecting to localhost
				InsecureSkipVerify: isLocalhost(host),
			},
		}
	}

	// Connect
	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// IsReachable checks if the daemon is reachable
func (c *APIClient) IsReachable() bool {
	resp, err := c.Get("/health")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
