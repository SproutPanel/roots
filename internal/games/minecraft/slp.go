// Package minecraft provides Minecraft-specific protocol implementations
package minecraft

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

// PlayerInfo represents a single online player
type PlayerInfo struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

// ServerStatus represents the response from a Server List Ping
type ServerStatus struct {
	Online  int          `json:"online"`
	Max     int          `json:"max"`
	Players []PlayerInfo `json:"players"`
	MOTD    string       `json:"motd,omitempty"`
	Version string       `json:"version,omitempty"`
}

// slpResponse is the raw JSON structure from Minecraft SLP
type slpResponse struct {
	Version struct {
		Name     string `json:"name"`
		Protocol int    `json:"protocol"`
	} `json:"version"`
	Players struct {
		Max    int `json:"max"`
		Online int `json:"online"`
		Sample []struct {
			Name string `json:"name"`
			ID   string `json:"id"`
		} `json:"sample"`
	} `json:"players"`
	Description interface{} `json:"description"`
}

// PingServer performs a Server List Ping to get player information
func PingServer(host string, port int) (*ServerStatus, error) {
	address := fmt.Sprintf("%s:%d", host, port)

	// Connect with timeout
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	// Set read/write deadline
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send handshake packet
	if err := sendHandshake(conn, host, port); err != nil {
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	// Send status request
	if err := sendStatusRequest(conn); err != nil {
		return nil, fmt.Errorf("status request failed: %w", err)
	}

	// Read status response
	response, err := readStatusResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return response, nil
}

// sendHandshake sends the handshake packet
func sendHandshake(conn net.Conn, host string, port int) error {
	var buf bytes.Buffer

	// Packet ID (0x00 for handshake)
	writeVarInt(&buf, 0x00)

	// Protocol version (use -1 for "any version" or 769 for 1.21.4)
	writeVarInt(&buf, -1)

	// Server address (string with length prefix)
	writeString(&buf, host)

	// Server port (unsigned short, big endian)
	binary.Write(&buf, binary.BigEndian, uint16(port))

	// Next state (1 = status)
	writeVarInt(&buf, 1)

	// Send as packet with length prefix
	return sendPacket(conn, buf.Bytes())
}

// sendStatusRequest sends the status request packet
func sendStatusRequest(conn net.Conn) error {
	var buf bytes.Buffer
	// Packet ID (0x00 for status request)
	writeVarInt(&buf, 0x00)
	return sendPacket(conn, buf.Bytes())
}

// readStatusResponse reads and parses the status response
func readStatusResponse(conn net.Conn) (*ServerStatus, error) {
	// Read packet length
	packetLen, err := readVarInt(conn)
	if err != nil {
		return nil, err
	}

	if packetLen > 1024*1024 { // Max 1MB
		return nil, fmt.Errorf("packet too large: %d bytes", packetLen)
	}

	// Read packet data
	data := make([]byte, packetLen)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}

	reader := bytes.NewReader(data)

	// Read packet ID
	packetID, err := readVarIntFromReader(reader)
	if err != nil {
		return nil, err
	}

	if packetID != 0x00 {
		return nil, fmt.Errorf("unexpected packet ID: %d", packetID)
	}

	// Read JSON string
	jsonStr, err := readString(reader)
	if err != nil {
		return nil, err
	}

	// Parse JSON
	var raw slpResponse
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Convert to our format
	status := &ServerStatus{
		Online:  raw.Players.Online,
		Max:     raw.Players.Max,
		Players: make([]PlayerInfo, 0, len(raw.Players.Sample)),
		Version: raw.Version.Name,
		MOTD:    extractMOTD(raw.Description),
	}

	for _, p := range raw.Players.Sample {
		status.Players = append(status.Players, PlayerInfo{
			Name: p.Name,
			UUID: p.ID,
		})
	}

	return status, nil
}

// extractMOTD extracts the MOTD from the description field
func extractMOTD(desc interface{}) string {
	switch v := desc.(type) {
	case string:
		return v
	case map[string]interface{}:
		if text, ok := v["text"].(string); ok {
			return text
		}
		// Handle component format with "extra" array
		if extra, ok := v["extra"].([]interface{}); ok {
			var result string
			for _, e := range extra {
				if m, ok := e.(map[string]interface{}); ok {
					if text, ok := m["text"].(string); ok {
						result += text
					}
				}
			}
			if result != "" {
				return result
			}
		}
	}
	return ""
}

// sendPacket sends a packet with its length prefix
func sendPacket(conn net.Conn, data []byte) error {
	var buf bytes.Buffer
	writeVarInt(&buf, int32(len(data)))
	buf.Write(data)
	_, err := conn.Write(buf.Bytes())
	return err
}

// writeVarInt writes a VarInt to the buffer
func writeVarInt(buf *bytes.Buffer, value int32) {
	// Convert to unsigned for proper bit shifting
	uval := uint32(value)
	for {
		temp := byte(uval & 0x7F)
		uval >>= 7
		if uval != 0 {
			temp |= 0x80
		}
		buf.WriteByte(temp)
		if uval == 0 {
			break
		}
	}
}

// writeString writes a length-prefixed string
func writeString(buf *bytes.Buffer, s string) {
	writeVarInt(buf, int32(len(s)))
	buf.WriteString(s)
}

// readVarInt reads a VarInt from a connection
func readVarInt(conn net.Conn) (int32, error) {
	var result int32
	var shift uint
	buf := make([]byte, 1)

	for {
		if _, err := conn.Read(buf); err != nil {
			return 0, err
		}
		result |= int32(buf[0]&0x7F) << shift
		if buf[0]&0x80 == 0 {
			break
		}
		shift += 7
		if shift >= 35 {
			return 0, fmt.Errorf("VarInt too large")
		}
	}
	return result, nil
}

// readVarIntFromReader reads a VarInt from a bytes.Reader
func readVarIntFromReader(reader *bytes.Reader) (int32, error) {
	var result int32
	var shift uint

	for {
		b, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		result |= int32(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
		if shift >= 35 {
			return 0, fmt.Errorf("VarInt too large")
		}
	}
	return result, nil
}

// readString reads a length-prefixed string
func readString(reader *bytes.Reader) (string, error) {
	length, err := readVarIntFromReader(reader)
	if err != nil {
		return "", err
	}

	if length < 0 || length > 32767 {
		return "", fmt.Errorf("string length out of range: %d", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(reader, data); err != nil {
		return "", err
	}

	return string(data), nil
}
