package main

import (
	"fmt"
	"os"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func reloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Reload daemon configuration",
		Long:  "Hot reload the daemon configuration from disk without restarting servers.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReload()
		},
	}
}

func runReload() error {
	p := tea.NewProgram(newReloadModel())
	_, err := p.Run()
	return err
}

// --- Bubbletea model for reload ---

type reloadModel struct {
	spinner spinner.Model
	done    bool
	success bool
	message string
}

type reloadResultMsg struct {
	success bool
	message string
}

func newReloadModel() reloadModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	return reloadModel{spinner: s}
}

func (m reloadModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		doReloadCmd(),
	)
}

func (m reloadModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case reloadResultMsg:
		m.done = true
		m.success = msg.success
		m.message = msg.message
		return m, tea.Quit

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m reloadModel) View() string {
	useColors := term.IsTerminal(int(os.Stdout.Fd()))

	green := lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("1"))

	if !useColors {
		green = lipgloss.NewStyle()
		red = lipgloss.NewStyle()
	}

	if m.done {
		if m.success {
			return fmt.Sprintf("\n  %s %s\n\n", green.Render("✓"), m.message)
		}
		return fmt.Sprintf("\n  %s %s\n\n", red.Render("✗"), m.message)
	}
	return fmt.Sprintf("\n  %s Reloading configuration...\n\n", m.spinner.View())
}

func doReloadCmd() tea.Cmd {
	return func() tea.Msg {
		client, err := NewAPIClient()
		if err != nil {
			return reloadResultMsg{
				success: false,
				message: fmt.Sprintf("Failed to connect: %v", err),
			}
		}

		resp, err := client.Post("/api/reload", nil)
		if err != nil {
			return reloadResultMsg{
				success: false,
				message: fmt.Sprintf("Request failed: %v", err),
			}
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return reloadResultMsg{
				success: false,
				message: fmt.Sprintf("Reload failed (status %d)", resp.StatusCode),
			}
		}

		return reloadResultMsg{
			success: true,
			message: "Configuration reloaded successfully",
		}
	}
}
