package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"
	"github.com/sproutpanel/roots/internal/config"
	"golang.org/x/term"
)

// DiagnosticCheck represents a single diagnostic check result
type DiagnosticCheck struct {
	Name    string
	Status  string // "pass", "fail", "warn"
	Message string
}

// DiagnosticsResult holds all diagnostic results
type DiagnosticsResult struct {
	LocalChecks  []DiagnosticCheck
	DaemonChecks []DiagnosticCheck
	DaemonOnline bool
}

func diagnosticsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diagnostics",
		Short: "Run system diagnostics",
		Long:  "Perform local and daemon health checks to troubleshoot issues.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiagnostics()
		},
	}
}

func runDiagnostics() error {
	p := tea.NewProgram(newDiagnosticsModel())
	_, err := p.Run()
	return err
}

// --- Bubbletea model for diagnostics ---

type diagnosticsModel struct {
	spinner  spinner.Model
	result   *DiagnosticsResult
	done     bool
	phase    string // "local", "daemon", "done"
}

type diagnosticsMsg DiagnosticsResult

func newDiagnosticsModel() diagnosticsModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	return diagnosticsModel{
		spinner: s,
		phase:   "local",
	}
}

func (m diagnosticsModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		runDiagnosticsCmd(),
	)
}

func (m diagnosticsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case diagnosticsMsg:
		result := DiagnosticsResult(msg)
		m.result = &result
		m.done = true
		return m, tea.Quit

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m diagnosticsModel) View() string {
	if m.done && m.result != nil {
		return renderDiagnostics(*m.result)
	}
	return fmt.Sprintf("\n  %s Running diagnostics...\n\n", m.spinner.View())
}

func runDiagnosticsCmd() tea.Cmd {
	return func() tea.Msg {
		return diagnosticsMsg(performDiagnostics())
	}
}

func performDiagnostics() DiagnosticsResult {
	result := DiagnosticsResult{}

	// --- Local Checks ---

	// 1. Configuration file
	cfg, err := config.Load(configPath)
	if err != nil {
		result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
			Name:    "Configuration",
			Status:  "fail",
			Message: fmt.Sprintf("Failed to load: %v", err),
		})
	} else if err := cfg.Validate(); err != nil {
		result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
			Name:    "Configuration",
			Status:  "fail",
			Message: fmt.Sprintf("Invalid: %v", err),
		})
	} else {
		result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
			Name:    "Configuration",
			Status:  "pass",
			Message: configPath,
		})
	}

	// 2. Docker socket
	dockerSocket := "/var/run/docker.sock"
	if cfg != nil && cfg.Docker.Socket != "" {
		dockerSocket = cfg.Docker.Socket
	}

	dockerClient, err := client.NewClientWithOpts(
		client.WithHost("unix://"+dockerSocket),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
			Name:    "Docker socket",
			Status:  "fail",
			Message: fmt.Sprintf("Cannot connect: %v", err),
		})
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := dockerClient.Ping(ctx)
		cancel()
		dockerClient.Close()

		if err != nil {
			result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
				Name:    "Docker socket",
				Status:  "fail",
				Message: fmt.Sprintf("Not responding: %v", err),
			})
		} else {
			result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
				Name:    "Docker socket",
				Status:  "pass",
				Message: dockerSocket,
			})
		}
	}

	// 3. Storage paths
	if cfg != nil {
		// Servers directory
		if info, err := os.Stat(cfg.Storage.Servers); err != nil {
			result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
				Name:    "Servers storage",
				Status:  "fail",
				Message: fmt.Sprintf("Not accessible: %v", err),
			})
		} else if !info.IsDir() {
			result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
				Name:    "Servers storage",
				Status:  "fail",
				Message: "Path is not a directory",
			})
		} else {
			// Check writable by creating temp file
			testFile := cfg.Storage.Servers + "/.roots-test"
			if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
				result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
					Name:    "Servers storage",
					Status:  "warn",
					Message: fmt.Sprintf("Not writable: %v", err),
				})
			} else {
				os.Remove(testFile)
				result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
					Name:    "Servers storage",
					Status:  "pass",
					Message: cfg.Storage.Servers,
				})
			}
		}

		// Backups directory
		if info, err := os.Stat(cfg.Storage.Backups); err != nil {
			result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
				Name:    "Backups storage",
				Status:  "fail",
				Message: fmt.Sprintf("Not accessible: %v", err),
			})
		} else if !info.IsDir() {
			result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
				Name:    "Backups storage",
				Status:  "fail",
				Message: "Path is not a directory",
			})
		} else {
			testFile := cfg.Storage.Backups + "/.roots-test"
			if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
				result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
					Name:    "Backups storage",
					Status:  "warn",
					Message: fmt.Sprintf("Not writable: %v", err),
				})
			} else {
				os.Remove(testFile)
				result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
					Name:    "Backups storage",
					Status:  "pass",
					Message: cfg.Storage.Backups,
				})
			}
		}
	}

	// 4. Port availability (only if daemon not running)
	if cfg != nil {
		apiAddr := fmt.Sprintf("%s:%d", cfg.Daemon.Host, cfg.Daemon.Port)
		if cfg.Daemon.Host == "0.0.0.0" {
			apiAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Daemon.Port)
		}

		conn, err := net.DialTimeout("tcp", apiAddr, 2*time.Second)
		if err != nil {
			// Port not in use - good if daemon should be down
			result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
				Name:    "API port",
				Status:  "pass",
				Message: fmt.Sprintf("Port %d available", cfg.Daemon.Port),
			})
		} else {
			conn.Close()
			// Port in use - might be our daemon or something else
			result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
				Name:    "API port",
				Status:  "pass",
				Message: fmt.Sprintf("Port %d in use (daemon may be running)", cfg.Daemon.Port),
			})
		}

		// Check SFTP port if enabled
		if cfg.SFTP.Enabled {
			sftpAddr := fmt.Sprintf("127.0.0.1:%d", cfg.SFTP.Port)
			conn, err := net.DialTimeout("tcp", sftpAddr, 2*time.Second)
			if err != nil {
				result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
					Name:    "SFTP port",
					Status:  "pass",
					Message: fmt.Sprintf("Port %d available", cfg.SFTP.Port),
				})
			} else {
				conn.Close()
				result.LocalChecks = append(result.LocalChecks, DiagnosticCheck{
					Name:    "SFTP port",
					Status:  "pass",
					Message: fmt.Sprintf("Port %d in use (daemon may be running)", cfg.SFTP.Port),
				})
			}
		}
	}

	// --- Daemon Checks ---

	apiClient, err := NewAPIClient()
	if err != nil {
		result.DaemonChecks = append(result.DaemonChecks, DiagnosticCheck{
			Name:    "Daemon connection",
			Status:  "fail",
			Message: fmt.Sprintf("Cannot connect: %v", err),
		})
		return result
	}

	// Check daemon status
	start := time.Now()
	resp, err := apiClient.Get("/status")
	latency := time.Since(start)

	if err != nil {
		result.DaemonOnline = false
		result.DaemonChecks = append(result.DaemonChecks, DiagnosticCheck{
			Name:    "Daemon connection",
			Status:  "fail",
			Message: "Daemon not responding",
		})
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		result.DaemonOnline = false
		result.DaemonChecks = append(result.DaemonChecks, DiagnosticCheck{
			Name:    "Daemon connection",
			Status:  "fail",
			Message: fmt.Sprintf("Unexpected status: %d", resp.StatusCode),
		})
		return result
	}

	result.DaemonOnline = true
	result.DaemonChecks = append(result.DaemonChecks, DiagnosticCheck{
		Name:    "Daemon connection",
		Status:  "pass",
		Message: fmt.Sprintf("Responding (latency: %dms)", latency.Milliseconds()),
	})

	// Get node stats for resource warnings
	statsResp, err := apiClient.Get("/api/node/status")
	if err == nil && statsResp.StatusCode == 200 {
		defer statsResp.Body.Close()

		data := fetchStatusData()
		if data.MemoryTotal > 0 {
			if data.MemoryPercent > 90 {
				result.DaemonChecks = append(result.DaemonChecks, DiagnosticCheck{
					Name:    "Memory usage",
					Status:  "fail",
					Message: fmt.Sprintf("Critical: %.0f%% used", data.MemoryPercent),
				})
			} else if data.MemoryPercent > 80 {
				result.DaemonChecks = append(result.DaemonChecks, DiagnosticCheck{
					Name:    "Memory usage",
					Status:  "warn",
					Message: fmt.Sprintf("High: %.0f%% used", data.MemoryPercent),
				})
			} else {
				result.DaemonChecks = append(result.DaemonChecks, DiagnosticCheck{
					Name:    "Memory usage",
					Status:  "pass",
					Message: fmt.Sprintf("%.0f%% used", data.MemoryPercent),
				})
			}

			if data.DiskPercent > 90 {
				result.DaemonChecks = append(result.DaemonChecks, DiagnosticCheck{
					Name:    "Disk usage",
					Status:  "fail",
					Message: fmt.Sprintf("Critical: %.0f%% used", data.DiskPercent),
				})
			} else if data.DiskPercent > 80 {
				result.DaemonChecks = append(result.DaemonChecks, DiagnosticCheck{
					Name:    "Disk usage",
					Status:  "warn",
					Message: fmt.Sprintf("High: %.0f%% used", data.DiskPercent),
				})
			} else {
				result.DaemonChecks = append(result.DaemonChecks, DiagnosticCheck{
					Name:    "Disk usage",
					Status:  "pass",
					Message: fmt.Sprintf("%.0f%% used", data.DiskPercent),
				})
			}
		}

		if data.DockerStatus == "connected" {
			result.DaemonChecks = append(result.DaemonChecks, DiagnosticCheck{
				Name:    "Docker status",
				Status:  "pass",
				Message: "Connected",
			})
		} else {
			result.DaemonChecks = append(result.DaemonChecks, DiagnosticCheck{
				Name:    "Docker status",
				Status:  "fail",
				Message: data.DockerStatus,
			})
		}
	}

	return result
}

func renderDiagnostics(result DiagnosticsResult) string {
	useColors := term.IsTerminal(int(os.Stdout.Fd()))

	// Styles
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	yellow := lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	bold := lipgloss.NewStyle().Bold(true)

	if !useColors {
		dim = lipgloss.NewStyle()
		green = lipgloss.NewStyle()
		yellow = lipgloss.NewStyle()
		red = lipgloss.NewStyle()
		bold = lipgloss.NewStyle()
	}

	var s string
	s += "\n"
	s += fmt.Sprintf("  %s\n", bold.Render("Local Checks"))
	s += "\n"

	for _, check := range result.LocalChecks {
		icon := green.Render("✓")
		if check.Status == "warn" {
			icon = yellow.Render("!")
		} else if check.Status == "fail" {
			icon = red.Render("✗")
		}
		s += fmt.Sprintf("  %s %s %s\n", icon, check.Name, dim.Render(check.Message))
	}

	s += "\n"
	s += fmt.Sprintf("  %s\n", bold.Render("Daemon Checks"))
	s += "\n"

	if len(result.DaemonChecks) == 0 {
		s += fmt.Sprintf("  %s\n", dim.Render("No daemon checks performed"))
	} else {
		for _, check := range result.DaemonChecks {
			icon := green.Render("✓")
			if check.Status == "warn" {
				icon = yellow.Render("!")
			} else if check.Status == "fail" {
				icon = red.Render("✗")
			}
			s += fmt.Sprintf("  %s %s %s\n", icon, check.Name, dim.Render(check.Message))
		}
	}

	s += "\n"

	// Summary
	passCount := 0
	warnCount := 0
	failCount := 0
	for _, c := range result.LocalChecks {
		switch c.Status {
		case "pass":
			passCount++
		case "warn":
			warnCount++
		case "fail":
			failCount++
		}
	}
	for _, c := range result.DaemonChecks {
		switch c.Status {
		case "pass":
			passCount++
		case "warn":
			warnCount++
		case "fail":
			failCount++
		}
	}

	if failCount > 0 {
		s += fmt.Sprintf("  %s\n", red.Render(fmt.Sprintf("✗ %d failed, %d warnings, %d passed", failCount, warnCount, passCount)))
	} else if warnCount > 0 {
		s += fmt.Sprintf("  %s\n", yellow.Render(fmt.Sprintf("! %d warnings, %d passed", warnCount, passCount)))
	} else {
		s += fmt.Sprintf("  %s\n", green.Render(fmt.Sprintf("✓ All %d checks passed", passCount)))
	}
	s += "\n"

	return s
}
