package minecraft

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// RCON packet types
	rconTypeCommand  int32 = 2
	rconTypeLogin    int32 = 3
	rconTypeResponse int32 = 0

	// Max packet size
	rconMaxPacketSize = 4096
)

var (
	ErrAuthFailed     = errors.New("rcon authentication failed")
	ErrNotConnected   = errors.New("rcon not connected")
	ErrResponseTooBig = errors.New("rcon response too large")
)

// RCONClient represents an RCON connection to a Minecraft server
type RCONClient struct {
	conn   net.Conn
	reqID  int32
	mu     sync.Mutex
}

// NewRCONClient creates a new RCON client and authenticates
func NewRCONClient(host string, port int, password string) (*RCONClient, error) {
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("rcon connection failed: %w", err)
	}

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	client := &RCONClient{
		conn:  conn,
		reqID: 1,
	}

	// Authenticate
	if err := client.authenticate(password); err != nil {
		conn.Close()
		return nil, err
	}

	return client, nil
}

// authenticate sends the login packet and verifies the response
func (c *RCONClient) authenticate(password string) error {
	reqID := c.nextReqID()

	if err := c.sendPacket(reqID, rconTypeLogin, password); err != nil {
		return fmt.Errorf("failed to send login packet: %w", err)
	}

	respID, _, _, err := c.readPacket()
	if err != nil {
		return fmt.Errorf("failed to read login response: %w", err)
	}

	// If response ID is -1, authentication failed
	if respID == -1 {
		return ErrAuthFailed
	}

	// Response ID should match our request ID
	if respID != reqID {
		return fmt.Errorf("unexpected response ID: got %d, want %d", respID, reqID)
	}

	return nil
}

// Execute sends a command and returns the response
func (c *RCONClient) Execute(command string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return "", ErrNotConnected
	}

	// Set deadline for this command
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))

	reqID := c.nextReqID()

	if err := c.sendPacket(reqID, rconTypeCommand, command); err != nil {
		return "", fmt.Errorf("failed to send command: %w", err)
	}

	respID, _, payload, err := c.readPacket()
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if respID != reqID {
		return "", fmt.Errorf("response ID mismatch: got %d, want %d", respID, reqID)
	}

	return payload, nil
}

// Close closes the RCON connection
func (c *RCONClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

// sendPacket writes an RCON packet to the connection
func (c *RCONClient) sendPacket(reqID, packetType int32, payload string) error {
	// Packet: length(4) + reqID(4) + type(4) + payload + null(1) + null(1)
	payloadBytes := []byte(payload)
	length := int32(4 + 4 + len(payloadBytes) + 1 + 1) // reqID + type + payload + 2 nulls

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, length)
	binary.Write(buf, binary.LittleEndian, reqID)
	binary.Write(buf, binary.LittleEndian, packetType)
	buf.Write(payloadBytes)
	buf.WriteByte(0) // null terminator for payload
	buf.WriteByte(0) // padding null

	_, err := c.conn.Write(buf.Bytes())
	return err
}

// readPacket reads an RCON packet from the connection
func (c *RCONClient) readPacket() (reqID, packetType int32, payload string, err error) {
	// Read length
	var length int32
	if err := binary.Read(c.conn, binary.LittleEndian, &length); err != nil {
		return 0, 0, "", err
	}

	if length > rconMaxPacketSize {
		return 0, 0, "", ErrResponseTooBig
	}

	// Read the rest of the packet
	data := make([]byte, length)
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return 0, 0, "", err
	}

	reader := bytes.NewReader(data)

	if err := binary.Read(reader, binary.LittleEndian, &reqID); err != nil {
		return 0, 0, "", err
	}

	if err := binary.Read(reader, binary.LittleEndian, &packetType); err != nil {
		return 0, 0, "", err
	}

	// Remaining bytes are payload (minus 2 null bytes at end)
	payloadLen := length - 4 - 4 - 2
	if payloadLen > 0 {
		payloadBytes := make([]byte, payloadLen)
		reader.Read(payloadBytes)
		payload = string(payloadBytes)
	}

	return reqID, packetType, payload, nil
}

func (c *RCONClient) nextReqID() int32 {
	c.reqID++
	return c.reqID
}

// ============================================================================
// Convenience methods for common Minecraft commands
// ============================================================================

// PlayersListResponse contains parsed player list data
type PlayersListResponse struct {
	Online  int          `json:"online"`
	Max     int          `json:"max"`
	Players []PlayerInfo `json:"players"`
}

// ListPlayers executes /list and parses the response
func (c *RCONClient) ListPlayers() (*PlayersListResponse, error) {
	resp, err := c.Execute("list")
	if err != nil {
		return nil, err
	}

	return parseListResponse(resp), nil
}

// parseListResponse parses the /list command output
// Formats:
// - Vanilla: "There are X of a max of Y players online: player1, player2"
// - Paper: "There are X of a max of Y players online: [group] player1, [group] player2"
// - Empty: "There are 0 of a max of 20 players online:"
func parseListResponse(resp string) *PlayersListResponse {
	result := &PlayersListResponse{
		Players: []PlayerInfo{},
	}

	// Match "There are X of a max of Y players online"
	countRegex := regexp.MustCompile(`There are (\d+) of a max of (\d+) players online`)
	matches := countRegex.FindStringSubmatch(resp)
	if len(matches) >= 3 {
		result.Online, _ = strconv.Atoi(matches[1])
		result.Max, _ = strconv.Atoi(matches[2])
	}

	// Extract player names after the colon
	colonIdx := strings.Index(resp, ":")
	if colonIdx != -1 && colonIdx < len(resp)-1 {
		playersPart := strings.TrimSpace(resp[colonIdx+1:])
		if playersPart != "" {
			// Split by comma and clean up
			names := strings.Split(playersPart, ",")
			for _, name := range names {
				name = strings.TrimSpace(name)
				// Remove group prefixes like "[Admin] " if present
				if bracketIdx := strings.Index(name, "]"); bracketIdx != -1 {
					name = strings.TrimSpace(name[bracketIdx+1:])
				}
				// Skip empty names or names that look like RCON messages
				if name == "" || strings.Contains(name, "There are") || strings.Contains(name, "players online") {
					continue
				}
				// Valid Minecraft names are 1-16 chars, alphanumeric + underscore
				if len(name) >= 1 && len(name) <= 16 && isValidMinecraftName(name) {
					result.Players = append(result.Players, PlayerInfo{
						Name: name,
						UUID: "", // RCON doesn't provide UUIDs
					})
				}
			}
		}
	}

	// Ensure online count matches actual parsed players
	// (in case some names were filtered out)
	result.Online = len(result.Players)

	return result
}

// isValidMinecraftName checks if a string is a valid Minecraft username
func isValidMinecraftName(name string) bool {
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// Kick kicks a player from the server
func (c *RCONClient) Kick(player, reason string) (string, error) {
	cmd := fmt.Sprintf("kick %s", player)
	if reason != "" {
		cmd = fmt.Sprintf("kick %s %s", player, reason)
	}
	return c.Execute(cmd)
}

// Ban bans a player from the server
func (c *RCONClient) Ban(player, reason string) (string, error) {
	cmd := fmt.Sprintf("ban %s", player)
	if reason != "" {
		cmd = fmt.Sprintf("ban %s %s", player, reason)
	}
	return c.Execute(cmd)
}

// Pardon unbans a player
func (c *RCONClient) Pardon(player string) (string, error) {
	return c.Execute(fmt.Sprintf("pardon %s", player))
}

// BanList gets the list of banned players
func (c *RCONClient) BanList() ([]string, error) {
	resp, err := c.Execute("banlist")
	if err != nil {
		return nil, err
	}
	return parseBanList(resp), nil
}

// parseBanList parses the banlist command output
func parseBanList(resp string) []string {
	var bans []string

	// Format: "There are X bans:\nplayer1, player2" or individual lines
	lines := strings.Split(resp, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "There are") {
			continue
		}
		if line == "" {
			continue
		}
		// Could be comma-separated or individual entries
		if strings.Contains(line, ",") {
			parts := strings.Split(line, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" {
					bans = append(bans, part)
				}
			}
		} else {
			bans = append(bans, line)
		}
	}

	return bans
}

// WhitelistList gets the whitelist
func (c *RCONClient) WhitelistList() ([]string, error) {
	resp, err := c.Execute("whitelist list")
	if err != nil {
		return nil, err
	}
	return parseWhitelist(resp), nil
}

// parseWhitelist parses whitelist list output
func parseWhitelist(resp string) []string {
	var players []string

	// Format: "There are X whitelisted players: player1, player2"
	colonIdx := strings.Index(resp, ":")
	if colonIdx != -1 && colonIdx < len(resp)-1 {
		playersPart := strings.TrimSpace(resp[colonIdx+1:])
		if playersPart != "" {
			names := strings.Split(playersPart, ",")
			for _, name := range names {
				name = strings.TrimSpace(name)
				if name != "" {
					players = append(players, name)
				}
			}
		}
	}

	return players
}

// WhitelistAdd adds a player to the whitelist
func (c *RCONClient) WhitelistAdd(player string) (string, error) {
	return c.Execute(fmt.Sprintf("whitelist add %s", player))
}

// WhitelistRemove removes a player from the whitelist
func (c *RCONClient) WhitelistRemove(player string) (string, error) {
	return c.Execute(fmt.Sprintf("whitelist remove %s", player))
}

// WhitelistOn enables the whitelist
func (c *RCONClient) WhitelistOn() (string, error) {
	return c.Execute("whitelist on")
}

// WhitelistOff disables the whitelist
func (c *RCONClient) WhitelistOff() (string, error) {
	return c.Execute("whitelist off")
}

// Op gives a player operator status
func (c *RCONClient) Op(player string) (string, error) {
	return c.Execute(fmt.Sprintf("op %s", player))
}

// Deop removes operator status from a player
func (c *RCONClient) Deop(player string) (string, error) {
	return c.Execute(fmt.Sprintf("deop %s", player))
}
