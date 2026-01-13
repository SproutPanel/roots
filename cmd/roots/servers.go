package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/charmbracelet/lipgloss"
	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// ServerInfo represents a server from the API
type ServerInfo struct {
	UUID        string         `json:"uuid"`
	PublicID    string         `json:"public_id"`
	Slug        string         `json:"slug"`
	Name        string         `json:"name"`
	Status      string         `json:"status"`
	Memory      int64          `json:"memory"`
	CPU         int64          `json:"cpu"`
	DiskLimit   int64          `json:"disk_limit"`
	Ports       map[string]int `json:"ports"`
	ContainerID string         `json:"container_id"`
}

func serversCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "servers",
		Short: "Manage game servers",
		Long:  "List and manage game servers on this node.",
		Run: func(cmd *cobra.Command, args []string) {
			// Default to list
			listServers()
		},
	}

	cmd.AddCommand(serversListCmd())
	cmd.AddCommand(serversStartCmd())
	cmd.AddCommand(serversStopCmd())
	cmd.AddCommand(serversRestartCmd())
	cmd.AddCommand(serversKillCmd())
	cmd.AddCommand(serversConsoleCmd())

	return cmd
}

func serversListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all servers",
		Run: func(cmd *cobra.Command, args []string) {
			listServers()
		},
	}
}

func serversStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start <server|all>",
		Short: "Start a server or all servers",
		Long:  "Start a server by slug, public ID, UUID, or use 'all' to start all servers.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if strings.ToLower(args[0]) == "all" {
				powerActionAll("start")
			} else {
				powerAction(args[0], "start")
			}
		},
	}
}

func serversStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop <server|all>",
		Short: "Stop a server or all servers gracefully",
		Long:  "Stop a server by slug, public ID, UUID, or use 'all' to stop all servers.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if strings.ToLower(args[0]) == "all" {
				powerActionAll("stop")
			} else {
				powerAction(args[0], "stop")
			}
		},
	}
}

func serversRestartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart <server|all>",
		Short: "Restart a server or all servers",
		Long:  "Restart a server by slug, public ID, UUID, or use 'all' to restart all servers.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if strings.ToLower(args[0]) == "all" {
				powerActionAll("restart")
			} else {
				powerAction(args[0], "restart")
			}
		},
	}
}

func serversKillCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "kill <server|all>",
		Short: "Force kill a server or all servers",
		Long:  "Force kill a server by slug, public ID, UUID, or use 'all' to kill all servers.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if strings.ToLower(args[0]) == "all" {
				powerActionAll("kill")
			} else {
				powerAction(args[0], "kill")
			}
		},
	}
}

func serversConsoleCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "console <server>",
		Short: "Attach to server console",
		Long:  "Attach to a server's console for real-time interaction. Specify server by slug, public ID, or UUID. Press Ctrl+C to detach.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			attachConsole(args[0])
		},
	}
}

func listServers() {
	client, err := NewAPIClient()
	if err != nil {
		printError("Failed to create client: %v", err)
		return
	}

	resp, err := client.Get("/api/servers")
	if err != nil {
		printError("Failed to connect to daemon: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		printError("Unexpected status: %d", resp.StatusCode)
		return
	}

	var servers []ServerInfo
	if err := json.NewDecoder(resp.Body).Decode(&servers); err != nil {
		printError("Failed to decode response: %v", err)
		return
	}

	if len(servers) == 0 {
		printDim("No servers found")
		return
	}

	// Build table
	printServerTable(servers)
}

func printServerTable(servers []ServerInfo) {
	useColors := term.IsTerminal(int(os.Stdout.Fd()))

	// Styles
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	greenStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	yellowStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	grayStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	if !useColors {
		headerStyle = lipgloss.NewStyle()
		dimStyle = lipgloss.NewStyle()
		greenStyle = lipgloss.NewStyle()
		yellowStyle = lipgloss.NewStyle()
		grayStyle = lipgloss.NewStyle()
	}

	// Print header
	fmt.Printf("\n  %s  %s  %s  %s  %s  %s\n",
		headerStyle.Width(20).Render("SLUG"),
		headerStyle.Width(16).Render("ID"),
		headerStyle.Width(12).Render("STATUS"),
		headerStyle.Width(10).Render("MEMORY"),
		headerStyle.Width(8).Render("PORT"),
		headerStyle.Width(20).Render("NAME"),
	)
	fmt.Printf("  %s\n", dimStyle.Render(strings.Repeat("─", 90)))

	// Print rows
	for _, s := range servers {
		// Format slug (truncate if needed)
		slug := s.Slug
		if slug == "" {
			slug = s.UUID[:8] // Fallback to UUID prefix if no slug
		}
		if len(slug) > 18 {
			slug = slug[:15] + "..."
		}

		// Format public ID
		publicID := s.PublicID
		if publicID == "" {
			publicID = s.UUID[:8] // Fallback to UUID prefix
		}

		// Format name (truncate if needed)
		name := s.Name
		if len(name) > 18 {
			name = name[:15] + "..."
		}

		// Format status with color
		var statusStr string
		switch s.Status {
		case "online":
			statusStr = greenStyle.Render("● online")
		case "starting", "stopping":
			statusStr = yellowStyle.Render("● " + s.Status)
		case "offline":
			statusStr = grayStyle.Render("○ offline")
		default:
			statusStr = grayStyle.Render("○ " + s.Status)
		}

		// Format memory
		memStr := "-"
		if s.Memory > 0 {
			memStr = formatBytes(s.Memory)
		}

		// Format port (get first port)
		portStr := "-"
		for _, port := range s.Ports {
			portStr = fmt.Sprintf("%d", port)
			break
		}

		fmt.Printf("  %s  %s  %s  %s  %s  %s\n",
			lipgloss.NewStyle().Width(20).Render(slug),
			dimStyle.Width(16).Render(publicID),
			lipgloss.NewStyle().Width(12).Render(statusStr),
			lipgloss.NewStyle().Width(10).Render(memStr),
			lipgloss.NewStyle().Width(8).Render(portStr),
			dimStyle.Width(20).Render(name),
		)
	}
	fmt.Println()
}

func powerAction(uuid, action string) {
	client, err := NewAPIClient()
	if err != nil {
		printError("Failed to create client: %v", err)
		return
	}

	// Resolve partial UUID
	fullUUID, serverName, err := resolveServerUUID(client, uuid)
	if err != nil {
		printError("%v", err)
		return
	}

	// Show action in progress
	actionVerb := map[string]string{
		"start":   "Starting",
		"stop":    "Stopping",
		"restart": "Restarting",
		"kill":    "Killing",
	}[action]
	printInfo("%s %s...", actionVerb, serverName)

	// Send power action
	resp, err := client.Post(fmt.Sprintf("/api/servers/%s/power", fullUUID), map[string]string{
		"action": action,
	})
	if err != nil {
		printError("Failed to send command: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		printError("Command failed (status %d)", resp.StatusCode)
		return
	}

	// Decode response to get new status
	var result struct {
		Status string `json:"status"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	// Show result
	switch result.Status {
	case "online":
		printSuccess("Server is now online")
	case "offline":
		printSuccess("Server is now offline")
	case "starting":
		printSuccess("Server is starting")
	case "stopping":
		printSuccess("Server is stopping")
	default:
		printSuccess("Server status: %s", result.Status)
	}
}

func powerActionAll(action string) {
	client, err := NewAPIClient()
	if err != nil {
		printError("Failed to create client: %v", err)
		return
	}

	// Fetch all servers
	resp, err := client.Get("/api/servers")
	if err != nil {
		printError("Failed to list servers: %v", err)
		return
	}
	defer resp.Body.Close()

	var servers []ServerInfo
	if err := json.NewDecoder(resp.Body).Decode(&servers); err != nil {
		printError("Failed to decode servers: %v", err)
		return
	}

	if len(servers) == 0 {
		printDim("No servers found")
		return
	}

	actionVerb := map[string]string{
		"start":   "Starting",
		"stop":    "Stopping",
		"restart": "Restarting",
		"kill":    "Killing",
	}[action]

	printInfo("%s all %d servers...", actionVerb, len(servers))
	fmt.Println()

	successCount := 0
	failCount := 0

	for _, server := range servers {
		printInfo("%s %s...", actionVerb, server.Name)

		resp, err := client.Post(fmt.Sprintf("/api/servers/%s/power", server.UUID), map[string]string{
			"action": action,
		})
		if err != nil {
			printError("  Failed: %v", err)
			failCount++
			continue
		}

		if resp.StatusCode != 200 {
			printError("  Failed (status %d)", resp.StatusCode)
			resp.Body.Close()
			failCount++
			continue
		}

		var result struct {
			Status string `json:"status"`
		}
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		switch result.Status {
		case "online":
			printSuccess("  Now online")
		case "offline":
			printSuccess("  Now offline")
		case "starting":
			printSuccess("  Starting")
		case "stopping":
			printSuccess("  Stopping")
		default:
			printSuccess("  Status: %s", result.Status)
		}
		successCount++
	}

	fmt.Println()
	if failCount == 0 {
		printSuccess("All %d servers processed successfully", successCount)
	} else {
		printInfo("%d succeeded, %d failed", successCount, failCount)
	}
}

func attachConsole(uuid string) {
	client, err := NewAPIClient()
	if err != nil {
		printError("Failed to create client: %v", err)
		return
	}

	// Resolve partial UUID and get server info
	server, err := resolveServer(client, uuid)
	if err != nil {
		printError("%v", err)
		return
	}

	// Check if server is running
	if server.Status != "online" && server.Status != "starting" {
		printError("Server is not running (status: %s)", server.Status)
		return
	}

	// Connect to WebSocket
	conn, err := client.WebSocket(fmt.Sprintf("/api/servers/%s/console", server.UUID))
	if err != nil {
		printError("Failed to connect to console: %v", err)
		return
	}
	defer conn.Close()

	printDim("Attached to %s. Press Ctrl+C to detach.\n", server.Name)

	// Set up signal handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Set terminal to raw mode for input
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		printError("Failed to set terminal mode: %v", err)
		return
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	// Channel to coordinate shutdown
	done := make(chan struct{})

	// Shared state for prompt redraw
	const prompt = "> "
	var lineBuf []byte
	var cursor int
	var inputMu sync.Mutex

	// Helper to clear and redraw the input line
	clearAndRedrawInput := func() {
		inputMu.Lock()
		defer inputMu.Unlock()
		// Move to start of input (after prompt)
		for i := 0; i < cursor; i++ {
			os.Stdout.Write([]byte("\b"))
		}
		// Clear prompt
		os.Stdout.Write([]byte("\b\b"))
		// Clear entire line content
		for i := 0; i < len(lineBuf)+2; i++ {
			os.Stdout.Write([]byte(" "))
		}
		for i := 0; i < len(lineBuf)+2; i++ {
			os.Stdout.Write([]byte("\b"))
		}
	}

	redrawInput := func() {
		inputMu.Lock()
		defer inputMu.Unlock()
		os.Stdout.Write([]byte(prompt))
		os.Stdout.Write(lineBuf)
		// Move cursor back to position
		for i := cursor; i < len(lineBuf); i++ {
			os.Stdout.Write([]byte("\b"))
		}
	}

	// Read from WebSocket and print to stdout
	go func() {
		defer close(done)
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				return
			}
			clearAndRedrawInput()
			os.Stdout.Write(message)
			redrawInput()
		}
	}()

	// Show initial prompt
	os.Stdout.Write([]byte(prompt))

	// Read from stdin with line editing and history support
	go func() {
		var history []string
		var historyPos int
		var savedLine []byte
		buf := make([]byte, 3)

		// Helper to clear current line and show new content
		replaceLine := func(newLine []byte) {
			// Move to start
			for cursor > 0 {
				os.Stdout.Write([]byte("\b"))
				cursor--
			}
			// Clear old content
			for i := 0; i < len(lineBuf); i++ {
				os.Stdout.Write([]byte(" "))
			}
			for i := 0; i < len(lineBuf); i++ {
				os.Stdout.Write([]byte("\b"))
			}
			// Write new content
			lineBuf = make([]byte, len(newLine))
			copy(lineBuf, newLine)
			os.Stdout.Write(lineBuf)
			cursor = len(lineBuf)
		}

		for {
			n, err := os.Stdin.Read(buf[:1])
			if err != nil || n == 0 {
				return
			}

			b := buf[0]

			switch b {
			case 0x03: // Ctrl+C to detach
				sigChan <- syscall.SIGINT
				return

			case 0x0D, 0x0A: // Enter
				inputMu.Lock()
				if len(lineBuf) == 0 {
					inputMu.Unlock()
					continue
				}
				// Add to history
				cmd := string(lineBuf)
				if len(history) == 0 || history[len(history)-1] != cmd {
					history = append(history, cmd)
				}
				historyPos = len(history)
				savedLine = nil

				// Clear entire line (move to start, then clear to end)
				// First, move cursor to start of line (before prompt)
				for i := 0; i < cursor; i++ {
					os.Stdout.Write([]byte("\b"))
				}
				os.Stdout.Write([]byte("\b\b")) // Past the prompt
				// Now clear from start to end of line with ANSI escape
				os.Stdout.Write([]byte("\x1b[K"))

				// Send command
				cmdToSend := lineBuf
				lineBuf = nil
				cursor = 0
				inputMu.Unlock()

				if err := conn.WriteMessage(websocket.TextMessage, cmdToSend); err != nil {
					return
				}

			case 0x7F, 0x08: // Backspace
				if cursor > 0 {
					copy(lineBuf[cursor-1:], lineBuf[cursor:])
					lineBuf = lineBuf[:len(lineBuf)-1]
					cursor--
					os.Stdout.Write([]byte("\b"))
					os.Stdout.Write(lineBuf[cursor:])
					os.Stdout.Write([]byte(" \b"))
					for i := cursor; i < len(lineBuf); i++ {
						os.Stdout.Write([]byte("\b"))
					}
				}

			case 0x1b: // Escape sequence (arrow keys)
				n, err := os.Stdin.Read(buf[1:3])
				if err != nil || n < 2 {
					continue
				}
				if buf[1] == '[' {
					switch buf[2] {
					case 'A': // Up arrow - previous history
						if len(history) > 0 && historyPos > 0 {
							if historyPos == len(history) {
								// Save current line before browsing history
								savedLine = make([]byte, len(lineBuf))
								copy(savedLine, lineBuf)
							}
							historyPos--
							replaceLine([]byte(history[historyPos]))
						}
					case 'B': // Down arrow - next history
						if historyPos < len(history) {
							historyPos++
							if historyPos == len(history) {
								// Restore saved line
								replaceLine(savedLine)
								savedLine = nil
							} else {
								replaceLine([]byte(history[historyPos]))
							}
						}
					case 'D': // Left arrow
						if cursor > 0 {
							cursor--
							os.Stdout.Write([]byte("\b"))
						}
					case 'C': // Right arrow
						if cursor < len(lineBuf) {
							os.Stdout.Write([]byte{lineBuf[cursor]})
							cursor++
						}
					case 'H': // Home
						for cursor > 0 {
							os.Stdout.Write([]byte("\b"))
							cursor--
						}
					case 'F': // End
						for cursor < len(lineBuf) {
							os.Stdout.Write([]byte{lineBuf[cursor]})
							cursor++
						}
					}
				}

			case 0x01: // Ctrl+A (Home)
				for cursor > 0 {
					os.Stdout.Write([]byte("\b"))
					cursor--
				}

			case 0x05: // Ctrl+E (End)
				for cursor < len(lineBuf) {
					os.Stdout.Write([]byte{lineBuf[cursor]})
					cursor++
				}

			case 0x0B: // Ctrl+K (Kill to end of line)
				// Clear from cursor to end
				for i := cursor; i < len(lineBuf); i++ {
					os.Stdout.Write([]byte(" "))
				}
				for i := cursor; i < len(lineBuf); i++ {
					os.Stdout.Write([]byte("\b"))
				}
				lineBuf = lineBuf[:cursor]

			case 0x15: // Ctrl+U (Kill to start of line)
				// Move to start, clear, redraw
				for cursor > 0 {
					os.Stdout.Write([]byte("\b"))
					cursor--
				}
				for range lineBuf {
					os.Stdout.Write([]byte(" "))
				}
				for range lineBuf {
					os.Stdout.Write([]byte("\b"))
				}
				lineBuf = nil
				cursor = 0

			default:
				if b >= 0x20 && b < 0x7F {
					inputMu.Lock()
					// Insert character at cursor (safe copy to avoid overlap issues)
					newBuf := make([]byte, len(lineBuf)+1)
					copy(newBuf[:cursor], lineBuf[:cursor])
					newBuf[cursor] = b
					copy(newBuf[cursor+1:], lineBuf[cursor:])
					lineBuf = newBuf
					// Clear to end of line, then redraw from cursor position
					os.Stdout.Write([]byte("\x1b[K"))
					os.Stdout.Write(lineBuf[cursor:])
					cursor++
					// Move cursor back to after inserted char
					for i := cursor; i < len(lineBuf); i++ {
						os.Stdout.Write([]byte("\b"))
					}
					inputMu.Unlock()
				}
			}
		}
	}()

	// Wait for signal or disconnect
	select {
	case <-sigChan:
		term.Restore(int(os.Stdin.Fd()), oldState)
		fmt.Println("\nDetached from console.")
	case <-done:
		term.Restore(int(os.Stdin.Fd()), oldState)
		fmt.Println("\nConnection closed.")
	}
}

func resolveServer(client *APIClient, identifier string) (*ServerInfo, error) {
	resp, err := client.Get("/api/servers")
	if err != nil {
		return nil, fmt.Errorf("failed to list servers: %w", err)
	}
	defer resp.Body.Close()

	var servers []ServerInfo
	if err := json.NewDecoder(resp.Body).Decode(&servers); err != nil {
		return nil, fmt.Errorf("failed to decode servers: %w", err)
	}

	// Try exact matches first (slug, public_id, uuid)
	for _, s := range servers {
		if s.Slug == identifier || s.PublicID == identifier || s.UUID == identifier {
			return &s, nil
		}
	}

	// Try prefix matches (uuid, public_id)
	var matches []ServerInfo
	for _, s := range servers {
		if strings.HasPrefix(s.UUID, identifier) ||
			strings.HasPrefix(s.PublicID, identifier) ||
			strings.Contains(strings.ToLower(s.Slug), strings.ToLower(identifier)) {
			matches = append(matches, s)
		}
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("no server found matching '%s'", identifier)
	}
	if len(matches) > 1 {
		// Show the matches to help user
		fmt.Println("Multiple servers match:")
		for _, m := range matches {
			fmt.Printf("  - %s (%s) [%s]\n", m.Slug, m.PublicID, m.Name)
		}
		return nil, fmt.Errorf("be more specific")
	}

	return &matches[0], nil
}

func resolveServerUUID(client *APIClient, partial string) (fullUUID, name string, err error) {
	server, err := resolveServer(client, partial)
	if err != nil {
		return "", "", err
	}
	return server.UUID, server.Name, nil
}

// Helper functions for output
func printError(format string, args ...interface{}) {
	useColors := term.IsTerminal(int(os.Stdout.Fd()))
	prefix := "✗"
	if useColors {
		prefix = "\033[31m✗\033[0m"
	}
	fmt.Printf("  %s %s\n", prefix, fmt.Sprintf(format, args...))
}

func printSuccess(format string, args ...interface{}) {
	useColors := term.IsTerminal(int(os.Stdout.Fd()))
	prefix := "✓"
	if useColors {
		prefix = "\033[32m✓\033[0m"
	}
	fmt.Printf("  %s %s\n", prefix, fmt.Sprintf(format, args...))
}

func printInfo(format string, args ...interface{}) {
	useColors := term.IsTerminal(int(os.Stdout.Fd()))
	prefix := "●"
	if useColors {
		prefix = "\033[36m●\033[0m"
	}
	fmt.Printf("  %s %s\n", prefix, fmt.Sprintf(format, args...))
}

func printDim(format string, args ...interface{}) {
	useColors := term.IsTerminal(int(os.Stdout.Fd()))
	msg := fmt.Sprintf(format, args...)
	if useColors {
		fmt.Printf("  \033[2m%s\033[0m\n", msg)
	} else {
		fmt.Printf("  %s\n", msg)
	}
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
