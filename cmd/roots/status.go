package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	watchMode     bool
	watchInterval int
)

func statusCmdEnhanced() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show daemon status",
		Long:  "Display the current status of the roots daemon, connected panel, and system resources.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if watchMode {
				return runStatusTUI()
			}
			return showStatusOnce()
		},
	}

	cmd.Flags().BoolVarP(&watchMode, "watch", "w", false, "Continuously update status")
	cmd.Flags().IntVar(&watchInterval, "interval", 5, "Update interval in seconds for watch mode")

	return cmd
}

// StatusData holds all status information
type StatusData struct {
	Online         bool
	Status         string
	Version        string
	UptimeHuman    string
	PanelURL       string
	ServersRunning int
	ServersStopped int
	DockerStatus   string
	// Node stats
	CPUPercent    float64
	CPUCores      int
	MemoryUsed    uint64
	MemoryTotal   uint64
	MemoryPercent float64
	DiskUsed      uint64
	DiskTotal     uint64
	DiskPercent   float64
	NetworkRx     uint64
	NetworkTx     uint64
	// Metadata
	LastUpdated time.Time
	Error       error
}

// showStatusOnce fetches and displays status once with a loading spinner
func showStatusOnce() error {
	p := tea.NewProgram(newOneShotModel())
	_, err := p.Run()
	return err
}

// --- One-shot status with spinner ---

type oneShotModel struct {
	spinner spinner.Model
	data    *StatusData
	done    bool
}

func newOneShotModel() oneShotModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	return oneShotModel{spinner: s}
}

func (m oneShotModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		fetchStatusCmd(),
	)
}

func (m oneShotModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case statusMsg:
		data := StatusData(msg)
		m.data = &data
		m.done = true
		return m, tea.Quit

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m oneShotModel) View() string {
	if m.done && m.data != nil {
		return renderStatus(*m.data, false)
	}
	return fmt.Sprintf("\n  %s Fetching status...\n\n", m.spinner.View())
}

// --- Bubbletea TUI for watch mode ---

type statusModel struct {
	data        StatusData
	interval    time.Duration
	nextRefresh time.Time
	quitting    bool
}

type tickMsg time.Time
type countdownMsg time.Time
type statusMsg StatusData

func (m statusModel) Init() tea.Cmd {
	m.nextRefresh = time.Now().Add(m.interval)
	return tea.Batch(
		fetchStatusCmd(),
		countdownTickCmd(),
	)
}

func (m statusModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.quitting = true
			return m, tea.Quit
		}

	case countdownMsg:
		// Check if it's time to refresh
		if time.Now().After(m.nextRefresh) {
			m.nextRefresh = time.Now().Add(m.interval)
			return m, tea.Batch(
				fetchStatusCmd(),
				countdownTickCmd(),
			)
		}
		// Just update the countdown display
		return m, countdownTickCmd()

	case statusMsg:
		m.data = StatusData(msg)
		return m, nil
	}

	return m, nil
}

func (m statusModel) View() string {
	if m.quitting {
		return ""
	}
	return renderStatusWithCountdown(m.data, m.nextRefresh)
}

func countdownTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return countdownMsg(t)
	})
}

func fetchStatusCmd() tea.Cmd {
	return func() tea.Msg {
		return statusMsg(fetchStatusData())
	}
}

func runStatusTUI() error {
	m := statusModel{
		interval:    time.Duration(watchInterval) * time.Second,
		nextRefresh: time.Now().Add(time.Duration(watchInterval) * time.Second),
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// --- Data fetching ---

func fetchStatusData() StatusData {
	data := StatusData{
		LastUpdated: time.Now(),
	}

	client, err := NewAPIClient()
	if err != nil {
		data.Error = err
		return data
	}

	// Fetch daemon status
	resp, err := client.Get("/status")
	if err != nil {
		data.Online = false
		return data
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		data.Online = false
		return data
	}

	var status struct {
		Status         string `json:"status"`
		Version        string `json:"version"`
		UptimeHuman    string `json:"uptime_human"`
		PanelURL       string `json:"panel_url"`
		ServersRunning int    `json:"servers_running"`
		ServersStopped int    `json:"servers_stopped"`
		DockerStatus   string `json:"docker_status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		data.Error = err
		return data
	}

	data.Online = true
	data.Status = status.Status
	data.Version = status.Version
	data.UptimeHuman = status.UptimeHuman
	data.PanelURL = status.PanelURL
	data.ServersRunning = status.ServersRunning
	data.ServersStopped = status.ServersStopped
	data.DockerStatus = status.DockerStatus

	// Fetch node stats (non-blocking, best effort)
	nodeResp, err := client.Get("/api/node/status")
	if err == nil && nodeResp.StatusCode == 200 {
		var nodeStats struct {
			CPUPercent    float64 `json:"CPUPercent"`
			CPUCores      int     `json:"CPUCores"`
			MemoryUsed    uint64  `json:"MemoryUsed"`
			MemoryTotal   uint64  `json:"MemoryTotal"`
			MemoryPercent float64 `json:"MemoryPercent"`
			DiskUsed      uint64  `json:"DiskUsed"`
			DiskTotal     uint64  `json:"DiskTotal"`
			DiskPercent   float64 `json:"DiskPercent"`
			NetworkRx     uint64  `json:"NetworkRx"`
			NetworkTx     uint64  `json:"NetworkTx"`
		}
		json.NewDecoder(nodeResp.Body).Decode(&nodeStats)
		nodeResp.Body.Close()

		data.CPUPercent = nodeStats.CPUPercent
		data.CPUCores = nodeStats.CPUCores
		data.MemoryUsed = nodeStats.MemoryUsed
		data.MemoryTotal = nodeStats.MemoryTotal
		data.MemoryPercent = nodeStats.MemoryPercent
		data.DiskUsed = nodeStats.DiskUsed
		data.DiskTotal = nodeStats.DiskTotal
		data.DiskPercent = nodeStats.DiskPercent
		data.NetworkRx = nodeStats.NetworkRx
		data.NetworkTx = nodeStats.NetworkTx
	}

	return data
}

// --- Rendering ---

func renderStatus(data StatusData, isWatch bool) string {
	useColors := term.IsTerminal(int(os.Stdout.Fd()))

	// Styles
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	yellow := lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	cyan := lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	bold := lipgloss.NewStyle().Bold(true)

	if !useColors {
		dim = lipgloss.NewStyle()
		green = lipgloss.NewStyle()
		yellow = lipgloss.NewStyle()
		cyan = lipgloss.NewStyle()
		red = lipgloss.NewStyle()
		bold = lipgloss.NewStyle()
	}

	var s string
	s += "\n"

	// Handle offline/error states
	if !data.Online {
		s += fmt.Sprintf("  %s     %s\n", dim.Render("Status"), red.Render("● Offline"))
		s += "\n"
		s += fmt.Sprintf("  %s\n", dim.Render("Daemon is not running. Start with: roots run"))
		s += "\n"
		return s
	}

	// Connected status
	s += fmt.Sprintf("  %s     %s\n", dim.Render("Status"), green.Render("● Connected"))
	s += fmt.Sprintf("  %s    %s\n", dim.Render("Version"), cyan.Render(data.Version))
	s += fmt.Sprintf("  %s      %s\n", dim.Render("Panel"), data.PanelURL)
	s += fmt.Sprintf("  %s     %s\n", dim.Render("Uptime"), bold.Render(data.UptimeHuman))

	// Docker status
	dockerIcon := green.Render("●")
	if data.DockerStatus != "connected" {
		dockerIcon = yellow.Render("●")
	}
	s += fmt.Sprintf("  %s     %s %s\n", dim.Render("Docker"), dockerIcon, data.DockerStatus)

	// Servers
	s += fmt.Sprintf("  %s    %s, %s\n",
		dim.Render("Servers"),
		green.Render(fmt.Sprintf("%d running", data.ServersRunning)),
		yellow.Render(fmt.Sprintf("%d stopped", data.ServersStopped)),
	)

	// System stats (if available)
	if data.MemoryTotal > 0 {
		s += "\n"
		s += fmt.Sprintf("  %s\n", dim.Render("System"))

		// CPU
		cpuStyle := green
		if data.CPUPercent > 80 {
			cpuStyle = yellow
		}
		s += fmt.Sprintf("    %s      %s (%s)\n",
			dim.Render("CPU"),
			cyan.Render(fmt.Sprintf("%d cores", data.CPUCores)),
			cpuStyle.Render(fmt.Sprintf("%.0f%% used", data.CPUPercent)),
		)

		// Memory
		memStyle := green
		if data.MemoryPercent > 80 {
			memStyle = yellow
		}
		s += fmt.Sprintf("    %s   %s / %s (%s)\n",
			dim.Render("Memory"),
			formatBytesShort(data.MemoryUsed),
			formatBytesShort(data.MemoryTotal),
			memStyle.Render(fmt.Sprintf("%.0f%%", data.MemoryPercent)),
		)

		// Disk
		diskStyle := green
		if data.DiskPercent > 80 {
			diskStyle = yellow
		}
		s += fmt.Sprintf("    %s     %s / %s (%s)\n",
			dim.Render("Disk"),
			formatBytesShort(data.DiskUsed),
			formatBytesShort(data.DiskTotal),
			diskStyle.Render(fmt.Sprintf("%.0f%%", data.DiskPercent)),
		)

		// Network
		s += fmt.Sprintf("    %s  %s  %s\n",
			dim.Render("Network"),
			cyan.Render(fmt.Sprintf("↑ %s/s", formatBytesShort(data.NetworkTx))),
			cyan.Render(fmt.Sprintf("↓ %s/s", formatBytesShort(data.NetworkRx))),
		)
	}

	s += "\n"

	if !isWatch {
		s += fmt.Sprintf("  %s\n", dim.Render("Use --watch for live updates"))
		s += "\n"
	}

	return s
}

func renderStatusWithCountdown(data StatusData, nextRefresh time.Time) string {
	useColors := term.IsTerminal(int(os.Stdout.Fd()))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	if !useColors {
		dim = lipgloss.NewStyle()
	}

	s := renderStatus(data, true)

	// Calculate countdown
	remaining := time.Until(nextRefresh)
	if remaining < 0 {
		remaining = 0
	}
	secs := int(remaining.Seconds())

	s += fmt.Sprintf("  %s\n", dim.Render(fmt.Sprintf("Next update in %ds • Press q or Ctrl+C to quit", secs)))
	s += "\n"

	return s
}

func formatBytesShort(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
