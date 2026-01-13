package logger

import (
	"fmt"
	"io"
	"os"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

// BannerConfig holds configuration for the startup banner
type BannerConfig struct {
	Version     string
	APIAddress  string
	SFTPAddress string
	SFTPEnabled bool
	DockerPath  string
	PanelURL    string
}

// PrintBanner prints a nice startup banner
func PrintBanner(w io.Writer, cfg BannerConfig) {
	useColors := false
	if f, ok := w.(*os.File); ok {
		useColors = term.IsTerminal(int(f.Fd()))
	}

	// Define styles
	var (
		green  = lipgloss.Color("2")
		cyan   = lipgloss.Color("6")
		subtle = lipgloss.Color("8")
	)

	borderStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(green).
		Padding(0, 1)

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(green)

	labelStyle := lipgloss.NewStyle().
		Foreground(cyan).
		Width(9)

	valueStyle := lipgloss.NewStyle()

	if !useColors {
		borderStyle = borderStyle.BorderForeground(lipgloss.NoColor{})
		titleStyle = titleStyle.Foreground(lipgloss.NoColor{}).Bold(false)
		labelStyle = labelStyle.Foreground(lipgloss.NoColor{})
	}

	// Build content
	title := fmt.Sprintf("🌱 %s v%s", titleStyle.Render("Roots"), cfg.Version)

	rows := []string{
		title,
		"",
		labelStyle.Render("API") + valueStyle.Render(cfg.APIAddress),
	}

	if cfg.SFTPEnabled {
		rows = append(rows, labelStyle.Render("SFTP")+valueStyle.Render(cfg.SFTPAddress))
	}

	rows = append(rows,
		labelStyle.Render("Docker")+valueStyle.Render(truncatePath(cfg.DockerPath, 44)),
		labelStyle.Render("Panel")+valueStyle.Render(truncatePath(cfg.PanelURL, 44)),
	)

	// Join rows and apply border
	content := lipgloss.JoinVertical(lipgloss.Left, rows...)
	box := borderStyle.Render(content)

	// Add indent
	indentStyle := lipgloss.NewStyle().PaddingLeft(2)
	output := indentStyle.Render(box)

	fmt.Fprintln(w)
	fmt.Fprintln(w, output)

	// Dim separator line
	if useColors {
		fmt.Fprintf(w, "  %s\n", lipgloss.NewStyle().Foreground(subtle).Render("─────────────────────────────────────────────────────────"))
	}
	fmt.Fprintln(w)
}

func truncatePath(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return "..." + s[len(s)-max+3:]
}
