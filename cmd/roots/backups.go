package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	idAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	idLength   = 12
)

// generateBackupID generates a backup ID matching the panel's format (bak_xxxxxxxxxxxx)
func generateBackupID() string {
	result := make([]byte, idLength)
	alphabetLen := big.NewInt(int64(len(idAlphabet)))

	for i := 0; i < idLength; i++ {
		n, _ := rand.Int(rand.Reader, alphabetLen)
		result[i] = idAlphabet[n.Int64()]
	}

	return "bak_" + string(result)
}

// BackupInfo represents a backup from the API
type BackupInfo struct {
	ID          string    `json:"id"`
	ServerUUID  string    `json:"server_uuid"`
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	Paths       []string  `json:"paths"`
	SizeBytes   int64     `json:"size_bytes"`
	Checksum    string    `json:"checksum"`
	ErrorMsg    string    `json:"error_message"`
	CreatedAt   time.Time `json:"created_at"`
	CompletedAt time.Time `json:"completed_at"`
}

func backupsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backups",
		Short: "Manage server backups",
		Long:  "List, create, and manage backups for game servers.",
	}

	cmd.AddCommand(backupsListCmd())
	cmd.AddCommand(backupsCreateCmd())
	cmd.AddCommand(backupsDeleteCmd())
	cmd.AddCommand(backupsRestoreCmd())

	return cmd
}

func backupsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list <server>",
		Short: "List backups for a server",
		Long:  "List all backups for a server. Specify server by slug, public ID, or UUID.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			listBackups(args[0])
		},
	}
}

func backupsCreateCmd() *cobra.Command {
	var name string
	var paths []string
	var uploadToS3 bool

	cmd := &cobra.Command{
		Use:   "create <server>",
		Short: "Create a backup for a server",
		Long:  "Create a new backup for a server. Specify server by slug, public ID, or UUID.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			createBackup(args[0], name, paths, uploadToS3)
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "", "Backup name (default: timestamp)")
	cmd.Flags().StringSliceVarP(&paths, "paths", "p", []string{"/"}, "Paths to backup (comma-separated)")
	cmd.Flags().BoolVar(&uploadToS3, "upload-to-s3", false, "Upload backup to S3 after completion")

	return cmd
}

func backupsDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <server> <backup-id>",
		Short: "Delete a backup",
		Long:  "Delete a backup by its ID. Specify server by slug, public ID, or UUID.",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			deleteBackup(args[0], args[1])
		},
	}
}

func backupsRestoreCmd() *cobra.Command {
	var paths []string

	cmd := &cobra.Command{
		Use:   "restore <server> <backup-id>",
		Short: "Restore a backup",
		Long:  "Restore a backup to the server. Server must be stopped. Specify server by slug, public ID, or UUID.",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			restoreBackup(args[0], args[1], paths)
		},
	}

	cmd.Flags().StringSliceVarP(&paths, "paths", "p", nil, "Only restore specific paths (comma-separated)")

	return cmd
}

func listBackups(serverIdentifier string) {
	client, err := NewAPIClient()
	if err != nil {
		printError("Failed to create client: %v", err)
		return
	}

	// Resolve server
	server, err := resolveServer(client, serverIdentifier)
	if err != nil {
		printError("%v", err)
		return
	}

	resp, err := client.Get(fmt.Sprintf("/api/servers/%s/backups", server.UUID))
	if err != nil {
		printError("Failed to connect to daemon: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		printError("Unexpected status: %d", resp.StatusCode)
		return
	}

	var backups []BackupInfo
	if err := json.NewDecoder(resp.Body).Decode(&backups); err != nil {
		printError("Failed to decode response: %v", err)
		return
	}

	if len(backups) == 0 {
		printDim("No backups found for %s", server.Name)
		return
	}

	printBackupTable(backups)
}

func printBackupTable(backups []BackupInfo) {
	useColors := term.IsTerminal(int(os.Stdout.Fd()))

	// Styles
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	greenStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	yellowStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	redStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	grayStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	if !useColors {
		headerStyle = lipgloss.NewStyle()
		dimStyle = lipgloss.NewStyle()
		greenStyle = lipgloss.NewStyle()
		yellowStyle = lipgloss.NewStyle()
		redStyle = lipgloss.NewStyle()
		grayStyle = lipgloss.NewStyle()
	}

	// Print header
	fmt.Printf("\n  %s  %s  %s  %s  %s\n",
		headerStyle.Width(20).Render("ID"),
		headerStyle.Width(12).Render("STATUS"),
		headerStyle.Width(10).Render("SIZE"),
		headerStyle.Width(20).Render("CREATED"),
		headerStyle.Width(24).Render("NAME"),
	)
	fmt.Printf("  %s\n", dimStyle.Render(strings.Repeat("─", 90)))

	// Print rows
	for _, b := range backups {
		// Format ID
		id := b.ID
		if len(id) > 18 {
			id = id[:15] + "..."
		}

		// Format status with color
		var statusStr string
		switch b.Status {
		case "completed":
			statusStr = greenStyle.Render("● completed")
		case "in_progress", "pending":
			statusStr = yellowStyle.Render("● " + b.Status)
		case "failed":
			statusStr = redStyle.Render("● failed")
		default:
			statusStr = grayStyle.Render("○ " + b.Status)
		}

		// Format size
		sizeStr := "-"
		if b.SizeBytes > 0 {
			sizeStr = formatBytes(b.SizeBytes)
		}

		// Format created time
		createdStr := b.CreatedAt.Format("Jan 02 15:04")

		// Format name (truncate if needed)
		name := b.Name
		if len(name) > 22 {
			name = name[:19] + "..."
		}

		fmt.Printf("  %s  %s  %s  %s  %s\n",
			dimStyle.Width(20).Render(id),
			lipgloss.NewStyle().Width(12).Render(statusStr),
			lipgloss.NewStyle().Width(10).Render(sizeStr),
			dimStyle.Width(20).Render(createdStr),
			lipgloss.NewStyle().Width(24).Render(name),
		)
	}
	fmt.Println()
}

func createBackup(serverIdentifier, name string, paths []string, uploadToS3 bool) {
	client, err := NewAPIClient()
	if err != nil {
		printError("Failed to create client: %v", err)
		return
	}

	// Resolve server
	server, err := resolveServer(client, serverIdentifier)
	if err != nil {
		printError("%v", err)
		return
	}

	// Generate backup ID and name
	backupID := generateBackupID()
	if name == "" {
		name = fmt.Sprintf("Backup %s", time.Now().Format("Jan 02 15:04"))
	}

	printInfo("Creating backup for %s...", server.Name)

	resp, err := client.Post(fmt.Sprintf("/api/servers/%s/backups", server.UUID), map[string]interface{}{
		"id":           backupID,
		"name":         name,
		"paths":        paths,
		"upload_to_s3": uploadToS3,
	})
	if err != nil {
		printError("Failed to create backup: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 202 {
		var result BackupInfo
		json.NewDecoder(resp.Body).Decode(&result)
		printSuccess("Backup started: %s", result.ID)
		printDim("Paths: %s", strings.Join(paths, ", "))
		if uploadToS3 {
			printDim("Will upload to S3 when complete")
		}
	} else if resp.StatusCode == 409 {
		printError("Backup already exists with this ID")
	} else {
		printError("Failed to create backup (status %d)", resp.StatusCode)
	}
}

func deleteBackup(serverIdentifier, backupID string) {
	client, err := NewAPIClient()
	if err != nil {
		printError("Failed to create client: %v", err)
		return
	}

	// Resolve server
	server, err := resolveServer(client, serverIdentifier)
	if err != nil {
		printError("%v", err)
		return
	}

	printInfo("Deleting backup %s...", backupID)

	resp, err := client.Delete(fmt.Sprintf("/api/servers/%s/backups/%s", server.UUID, backupID))
	if err != nil {
		printError("Failed to delete backup: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 204 {
		printSuccess("Backup deleted")
	} else if resp.StatusCode == 404 {
		printError("Backup not found")
	} else {
		printError("Failed to delete backup (status %d)", resp.StatusCode)
	}
}

func restoreBackup(serverIdentifier, backupID string, paths []string) {
	client, err := NewAPIClient()
	if err != nil {
		printError("Failed to create client: %v", err)
		return
	}

	// Resolve server
	server, err := resolveServer(client, serverIdentifier)
	if err != nil {
		printError("%v", err)
		return
	}

	// Check if server is running
	if server.Status == "online" || server.Status == "starting" {
		printError("Server must be stopped before restoring (current status: %s)", server.Status)
		return
	}

	printInfo("Restoring backup %s to %s...", backupID, server.Name)

	payload := map[string]interface{}{}
	if len(paths) > 0 {
		payload["paths"] = paths
	}

	resp, err := client.Post(fmt.Sprintf("/api/servers/%s/backups/%s/restore", server.UUID, backupID), payload)
	if err != nil {
		printError("Failed to restore backup: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		printSuccess("Backup restored successfully")
	} else if resp.StatusCode == 404 {
		printError("Backup not found")
	} else if resp.StatusCode == 400 {
		printError("Backup not ready for restore or server is running")
	} else {
		printError("Failed to restore backup (status %d)", resp.StatusCode)
	}
}
