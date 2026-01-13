// Package minecraft provides Minecraft server communication protocols
package minecraft

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// ManagementClient implements the Minecraft Server Management Protocol (1.21.9+)
// JSON-RPC 2.0 over WebSocket for server management
type ManagementClient struct {
	conn      *websocket.Conn
	url       string
	token     string
	requestID atomic.Int64
	mu        sync.Mutex

	// Response channels keyed by request ID
	pending   map[int64]chan *RPCResponse
	pendingMu sync.Mutex

	// Event handlers
	onPlayerJoin  func(player PlayerInfo)
	onPlayerLeave func(player PlayerInfo)
}

// RPCRequest is a JSON-RPC 2.0 request
type RPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	ID      int64       `json:"id"`
	Params  interface{} `json:"params,omitempty"`
}

// RPCResponse is a JSON-RPC 2.0 response
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is a JSON-RPC 2.0 error
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// RPCNotification is a JSON-RPC 2.0 notification (no ID)
type RPCNotification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// ManagementPlayer represents a player in the management protocol
type ManagementPlayer struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

// ManagementOperator represents an operator
type ManagementOperator struct {
	Player            ManagementPlayer `json:"player"`
	Level             int              `json:"level"`
	BypassPlayerLimit bool             `json:"bypassPlayerLimit"`
}

// ManagementBan represents a player ban
type ManagementBan struct {
	Player  ManagementPlayer `json:"player"`
	Reason  string           `json:"reason,omitempty"`
	Source  string           `json:"source,omitempty"`
	Expires string           `json:"expires,omitempty"` // ISO 8601 or empty for permanent
}

// ManagementIPBan represents an IP ban
type ManagementIPBan struct {
	IP      string `json:"ip"`
	Reason  string `json:"reason,omitempty"`
	Source  string `json:"source,omitempty"`
	Expires string `json:"expires,omitempty"`
}

// NewManagementClient creates a new Management Protocol client
func NewManagementClient(host string, port int, token string, useTLS bool) (*ManagementClient, error) {
	scheme := "ws"
	if useTLS {
		scheme = "wss"
	}

	url := fmt.Sprintf("%s://%s:%d", scheme, host, port)

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	if useTLS {
		dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // Server uses self-signed cert by default
		}
	}

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)

	conn, _, err := dialer.Dial(url, headers)
	if err != nil {
		return nil, fmt.Errorf("management protocol connection failed: %w", err)
	}

	client := &ManagementClient{
		conn:    conn,
		url:     url,
		token:   token,
		pending: make(map[int64]chan *RPCResponse),
	}

	// Start reading messages
	go client.readLoop()

	return client, nil
}

// Close closes the management protocol connection
func (c *ManagementClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// readLoop reads messages from the WebSocket
func (c *ManagementClient) readLoop() {
	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			return
		}

		// Try to parse as response first
		var resp RPCResponse
		if err := json.Unmarshal(message, &resp); err == nil && resp.ID != 0 {
			c.pendingMu.Lock()
			if ch, ok := c.pending[resp.ID]; ok {
				ch <- &resp
				delete(c.pending, resp.ID)
			}
			c.pendingMu.Unlock()
			continue
		}

		// Try to parse as notification
		var notif RPCNotification
		if err := json.Unmarshal(message, &notif); err == nil && notif.Method != "" {
			c.handleNotification(&notif)
		}
	}
}

// handleNotification processes server-sent notifications
func (c *ManagementClient) handleNotification(notif *RPCNotification) {
	switch notif.Method {
	case "minecraft:player/joined":
		if c.onPlayerJoin != nil {
			var player ManagementPlayer
			if err := json.Unmarshal(notif.Params, &player); err == nil {
				c.onPlayerJoin(PlayerInfo{Name: player.Name, UUID: player.UUID})
			}
		}
	case "minecraft:player/left":
		if c.onPlayerLeave != nil {
			var player ManagementPlayer
			if err := json.Unmarshal(notif.Params, &player); err == nil {
				c.onPlayerLeave(PlayerInfo{Name: player.Name, UUID: player.UUID})
			}
		}
	}
}

// call makes a JSON-RPC call and waits for response
func (c *ManagementClient) call(method string, params interface{}) (*RPCResponse, error) {
	id := c.requestID.Add(1)

	req := RPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		ID:      id,
		Params:  params,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	// Create response channel
	respCh := make(chan *RPCResponse, 1)
	c.pendingMu.Lock()
	c.pending[id] = respCh
	c.pendingMu.Unlock()

	// Send request
	c.mu.Lock()
	err = c.conn.WriteMessage(websocket.TextMessage, data)
	c.mu.Unlock()

	if err != nil {
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
		return nil, err
	}

	// Wait for response with timeout
	select {
	case resp := <-respCh:
		if resp.Error != nil {
			return nil, fmt.Errorf("RPC error %d: %s", resp.Error.Code, resp.Error.Message)
		}
		return resp, nil
	case <-time.After(10 * time.Second):
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
		return nil, fmt.Errorf("request timeout")
	}
}

// QueryPlayers returns all connected players with UUIDs
func (c *ManagementClient) QueryPlayers() ([]PlayerInfo, error) {
	resp, err := c.call("minecraft:players", nil)
	if err != nil {
		return nil, err
	}

	var players []ManagementPlayer
	if err := json.Unmarshal(resp.Result, &players); err != nil {
		return nil, err
	}

	result := make([]PlayerInfo, len(players))
	for i, p := range players {
		result[i] = PlayerInfo{Name: p.Name, UUID: p.UUID}
	}
	return result, nil
}

// KickPlayer kicks a player from the server
func (c *ManagementClient) KickPlayer(name, reason string) error {
	kickPlayer := map[string]interface{}{
		"player": map[string]string{"name": name},
	}
	if reason != "" {
		kickPlayer["message"] = map[string]string{"literal": reason}
	}

	params := map[string]interface{}{
		"kick": []interface{}{kickPlayer},
	}
	_, err := c.call("minecraft:players/kick", params)
	return err
}

// QueryAllowlist returns the server allowlist (whitelist)
func (c *ManagementClient) QueryAllowlist() ([]PlayerInfo, error) {
	resp, err := c.call("minecraft:allowlist", nil)
	if err != nil {
		return nil, err
	}

	var players []ManagementPlayer
	if err := json.Unmarshal(resp.Result, &players); err != nil {
		return nil, err
	}

	result := make([]PlayerInfo, len(players))
	for i, p := range players {
		result[i] = PlayerInfo{Name: p.Name, UUID: p.UUID}
	}
	return result, nil
}

// AddToAllowlist adds a player to the allowlist
func (c *ManagementClient) AddToAllowlist(name string) error {
	params := map[string]interface{}{
		"add": []map[string]string{{"name": name}},
	}
	_, err := c.call("minecraft:allowlist/add", params)
	return err
}

// RemoveFromAllowlist removes a player from the allowlist
func (c *ManagementClient) RemoveFromAllowlist(name string) error {
	params := map[string]interface{}{
		"remove": []map[string]string{{"name": name}},
	}
	_, err := c.call("minecraft:allowlist/remove", params)
	return err
}

// IsAllowlistEnabled checks if the allowlist is enabled on the server
func (c *ManagementClient) IsAllowlistEnabled() (bool, error) {
	resp, err := c.call("minecraft:serversettings/use_allowlist", nil)
	if err != nil {
		return false, err
	}

	var result struct {
		Use bool `json:"use"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return false, err
	}
	return result.Use, nil
}

// SetAllowlistEnabled enables or disables the allowlist on the server
func (c *ManagementClient) SetAllowlistEnabled(enabled bool) error {
	params := map[string]interface{}{
		"use": enabled,
	}
	_, err := c.call("minecraft:serversettings/use_allowlist/set", params)
	return err
}

// IsAllowlistEnforced checks if allowlist enforcement is enabled
// When enforced, players are kicked immediately upon removal from allowlist
func (c *ManagementClient) IsAllowlistEnforced() (bool, error) {
	resp, err := c.call("minecraft:serversettings/enforce_allowlist", nil)
	if err != nil {
		return false, err
	}

	var result struct {
		Enforced bool `json:"enforced"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return false, err
	}
	return result.Enforced, nil
}

// SetAllowlistEnforced enables or disables allowlist enforcement
// When enforced, players are kicked immediately upon removal from allowlist
func (c *ManagementClient) SetAllowlistEnforced(enforced bool) error {
	params := map[string]interface{}{
		"enforce": enforced,
	}
	_, err := c.call("minecraft:serversettings/enforce_allowlist/set", params)
	return err
}

// QueryBannedPlayers returns all banned players
func (c *ManagementClient) QueryBannedPlayers() ([]ManagementBan, error) {
	resp, err := c.call("minecraft:bans", nil)
	if err != nil {
		return nil, err
	}

	var bans []ManagementBan
	if err := json.Unmarshal(resp.Result, &bans); err != nil {
		return nil, err
	}
	return bans, nil
}

// BanPlayer bans a player
func (c *ManagementClient) BanPlayer(name, reason string) error {
	ban := map[string]interface{}{
		"player": map[string]string{"name": name},
	}
	if reason != "" {
		ban["reason"] = reason
	}

	params := map[string]interface{}{
		"add": []interface{}{ban},
	}
	_, err := c.call("minecraft:bans/add", params)
	return err
}

// UnbanPlayer removes a player ban
func (c *ManagementClient) UnbanPlayer(name string) error {
	params := map[string]interface{}{
		"remove": []map[string]string{{"name": name}},
	}
	_, err := c.call("minecraft:bans/remove", params)
	return err
}

// QueryIPBans returns all IP bans
func (c *ManagementClient) QueryIPBans() ([]ManagementIPBan, error) {
	resp, err := c.call("minecraft:ip_bans", nil)
	if err != nil {
		return nil, err
	}

	var bans []ManagementIPBan
	if err := json.Unmarshal(resp.Result, &bans); err != nil {
		return nil, err
	}
	return bans, nil
}

// BanIP bans an IP address
func (c *ManagementClient) BanIP(ip, reason string) error {
	ban := map[string]interface{}{
		"ip": ip,
	}
	if reason != "" {
		ban["reason"] = reason
	}

	params := map[string]interface{}{
		"add": []interface{}{ban},
	}
	_, err := c.call("minecraft:ip_bans/add", params)
	return err
}

// UnbanIP removes an IP ban
func (c *ManagementClient) UnbanIP(ip string) error {
	params := map[string]interface{}{
		"remove": []string{ip},
	}
	_, err := c.call("minecraft:ip_bans/remove", params)
	return err
}

// QueryOperators returns all operators
func (c *ManagementClient) QueryOperators() ([]ManagementOperator, error) {
	resp, err := c.call("minecraft:operators", nil)
	if err != nil {
		return nil, err
	}

	var ops []ManagementOperator
	if err := json.Unmarshal(resp.Result, &ops); err != nil {
		return nil, err
	}
	return ops, nil
}

// AddOperator makes a player an operator
func (c *ManagementClient) AddOperator(name string, level int) error {
	op := map[string]interface{}{
		"player":          map[string]string{"name": name},
		"permissionLevel": level,
	}

	params := map[string]interface{}{
		"add": []interface{}{op},
	}
	_, err := c.call("minecraft:operators/add", params)
	return err
}

// RemoveOperator removes operator status from a player
func (c *ManagementClient) RemoveOperator(name string) error {
	params := map[string]interface{}{
		"remove": []map[string]string{{"name": name}},
	}
	_, err := c.call("minecraft:operators/remove", params)
	return err
}

// QueryServerState returns the current server state
func (c *ManagementClient) QueryServerState() (*ServerState, error) {
	resp, err := c.call("minecraft:server/query", nil)
	if err != nil {
		return nil, err
	}

	var state ServerState
	if err := json.Unmarshal(resp.Result, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// ServerState represents the server state from the management protocol
type ServerState struct {
	Version struct {
		Name     string `json:"name"`
		Protocol int    `json:"protocol"`
	} `json:"version"`
	Players       []ManagementPlayer `json:"players"`
	StartupStatus string             `json:"startupStatus"` // "starting", "ready", "stopping"
}

// SetOnPlayerJoin sets the handler for player join events
func (c *ManagementClient) SetOnPlayerJoin(handler func(player PlayerInfo)) {
	c.onPlayerJoin = handler
}

// SetOnPlayerLeave sets the handler for player leave events
func (c *ManagementClient) SetOnPlayerLeave(handler func(player PlayerInfo)) {
	c.onPlayerLeave = handler
}

// TextComponent represents a Minecraft JSON text component with formatting
type TextComponent struct {
	Text          string `json:"text,omitempty"`
	Color         string `json:"color,omitempty"`
	Bold          bool   `json:"bold,omitempty"`
	Italic        bool   `json:"italic,omitempty"`
	Underlined    bool   `json:"underlined,omitempty"`
	Strikethrough bool   `json:"strikethrough,omitempty"`
	Obfuscated    bool   `json:"obfuscated,omitempty"`
}

// HasFormatting returns true if any formatting options are set
func (t TextComponent) HasFormatting() bool {
	return t.Color != "" || t.Bold || t.Italic || t.Underlined || t.Strikethrough || t.Obfuscated
}

// SendSystemMessage broadcasts a system message to all players (or specific players)
// If overlay is true, the message appears as an action bar message
func (c *ManagementClient) SendSystemMessage(message string, overlay bool, playerNames []string) error {
	return c.SendPlainSystemMessage(message, overlay, playerNames)
}

// SendPlainSystemMessage broadcasts a plain text message via Management Protocol
// Note: Management Protocol only supports plain text via "literal" field
// For formatted messages (color, bold, etc.), use RCON with /tellraw instead
func (c *ManagementClient) SendPlainSystemMessage(message string, overlay bool, playerNames []string) error {
	systemMessage := map[string]interface{}{
		"message": map[string]interface{}{
			"literal": message,
		},
		"overlay": overlay,
	}

	// If specific players are provided, add them
	if len(playerNames) > 0 {
		players := make([]map[string]string, len(playerNames))
		for i, name := range playerNames {
			players[i] = map[string]string{"name": name}
		}
		systemMessage["receivingPlayers"] = players
	}

	// params is an array containing the SystemMessage object
	params := []interface{}{systemMessage}

	_, err := c.call("minecraft:server/system_message", params)
	return err
}

// Gamerule represents a Minecraft gamerule with its current value
type Gamerule struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"` // Can be bool or int
	Type  string      `json:"type"`  // "boolean" or "integer"
}

// QueryGamerules returns all gamerules with their current values
func (c *ManagementClient) QueryGamerules() ([]Gamerule, error) {
	resp, err := c.call("minecraft:gamerules", nil)
	if err != nil {
		return nil, err
	}

	// Response is a direct array of gamerules
	var result []Gamerule
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Discover returns the RPC schema (for debugging)
func (c *ManagementClient) Discover() (json.RawMessage, error) {
	resp, err := c.call("rpc.discover", nil)
	if err != nil {
		return nil, err
	}
	return resp.Result, nil
}

// UpdateGamerule updates a gamerule value
// value should be a string representation (e.g., "true", "false", "10")
func (c *ManagementClient) UpdateGamerule(key string, value string) (*Gamerule, error) {
	// Parse value to proper type (boolean or integer, NOT string)
	var typedValue interface{}
	if value == "true" {
		typedValue = true
	} else if value == "false" {
		typedValue = false
	} else if i, err := strconv.Atoi(value); err == nil {
		typedValue = i
	} else {
		typedValue = value // fallback to string
	}

	// Params: {"gamerule": {"key": "...", "value": <bool|int>}}
	params := map[string]interface{}{
		"gamerule": map[string]interface{}{
			"key":   key,
			"value": typedValue,
		},
	}

	resp, err := c.call("minecraft:gamerules/update", params)
	if err != nil {
		return nil, err
	}

	// Response is the gamerule object directly (not wrapped)
	var result Gamerule
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// StopServer initiates a graceful server shutdown
func (c *ManagementClient) StopServer() error {
	_, err := c.call("minecraft:server/stop", nil)
	return err
}

// SaveServer triggers a world save
func (c *ManagementClient) SaveServer() error {
	_, err := c.call("minecraft:server/save", nil)
	return err
}

// Execute is not directly supported by Management Protocol (JSON-RPC based)
// This method exists to satisfy the ProtocolClient interface
// For raw command execution, use RCON instead
func (c *ManagementClient) Execute(command string) (string, error) {
	return "", fmt.Errorf("raw command execution not supported by Management Protocol, use RCON")
}
