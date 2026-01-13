package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/sproutpanel/roots/internal/api"
	"github.com/sproutpanel/roots/internal/config"
	"github.com/sproutpanel/roots/internal/docker"
	"github.com/sproutpanel/roots/internal/logger"
	"github.com/sproutpanel/roots/internal/sftp"
	"github.com/sproutpanel/roots/internal/version"
)

var (
	configPath string
	debug      bool
)

func getDefaultConfigPath() string {
	home, _ := os.UserHomeDir()
	return home + "/.config/roots/config.yaml"
}

func main() {
	rootCmd := &cobra.Command{
		Use:     "roots",
		Short:   "Roots - Game server management daemon",
		Long:    `Roots is the daemon component of SproutPanel that manages Docker containers for game servers.`,
		Version: version.Version,
	}

	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", getDefaultConfigPath(), "Path to config file")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")

	rootCmd.AddCommand(runCmd())
	rootCmd.AddCommand(configureCmd())
	rootCmd.AddCommand(validateCmd())
	rootCmd.AddCommand(statusCmdEnhanced())
	rootCmd.AddCommand(serversCmd())
	rootCmd.AddCommand(backupsCmd())
	rootCmd.AddCommand(diagnosticsCmd())
	rootCmd.AddCommand(reloadCmd())
	rootCmd.AddCommand(updateCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Start the Roots daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDaemon()
		},
	}
}

func configureCmd() *cobra.Command {
	var panelURL, token string
	var daemonPort int

	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Configure the Roots daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.DefaultConfig()

			// Load existing config if present
			existing, _ := config.Load(configPath)
			if existing != nil {
				cfg = existing
			}

			// Apply overrides
			if panelURL != "" {
				cfg.Panel.URL = panelURL
			}
			if token != "" {
				cfg.Panel.Token = token
			}
			if daemonPort > 0 {
				cfg.Daemon.Port = daemonPort
			}

			// Save config
			if err := cfg.Save(configPath); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}

			fmt.Printf("Configuration saved to %s\n", configPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&panelURL, "panel-url", "", "URL of the SproutPanel instance")
	cmd.Flags().StringVar(&token, "token", "", "Authentication token from the panel")
	cmd.Flags().IntVar(&daemonPort, "port", 0, "Port for the daemon API")

	return cmd
}

func validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate the configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("config validation failed: %w", err)
			}

			fmt.Println("Configuration is valid!")
			return nil
		},
	}
}

func runDaemon() error {
	// Setup logger with colorized output (auto-detects terminal)
	logLevel := slog.LevelInfo
	if debug {
		logLevel = slog.LevelDebug
	}

	log := slog.New(logger.NewColorHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	// Ensure storage directories exist
	if err := os.MkdirAll(cfg.Storage.Servers, 0755); err != nil {
		return fmt.Errorf("failed to create servers directory: %w", err)
	}
	if err := os.MkdirAll(cfg.Storage.Backups, 0755); err != nil {
		return fmt.Errorf("failed to create backups directory: %w", err)
	}

	// Create Docker client
	dockerClient, err := docker.NewClient(cfg.Docker.Socket, cfg.Docker.Network)
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}
	defer dockerClient.Close()

	// Test Docker connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := dockerClient.Ping(ctx); err != nil {
		cancel()
		return fmt.Errorf("failed to connect to Docker: %w", err)
	}
	cancel()

	// Print startup banner first
	sftpAddr := ""
	if cfg.SFTP.Enabled {
		sftpAddr = fmt.Sprintf("%s:%d", cfg.Daemon.Host, cfg.SFTP.Port)
	}
	logger.PrintBanner(os.Stdout, logger.BannerConfig{
		Version:     version.Version,
		APIAddress:  fmt.Sprintf("%s:%d", cfg.Daemon.Host, cfg.Daemon.Port),
		SFTPAddress: sftpAddr,
		SFTPEnabled: cfg.SFTP.Enabled,
		DockerPath:  cfg.Docker.Socket,
		PanelURL:    cfg.Panel.URL,
	})

	// Create API server (loads servers)
	server := api.NewServer(cfg, configPath, dockerClient, log)
	log.Info("Ready", "servers", server.ServerCount())

	// Create SFTP server (if enabled)
	var sftpServer *sftp.Server
	if cfg.SFTP.Enabled {
		var err error
		sftpServer, err = sftp.NewServer(cfg, log)
		if err != nil {
			return fmt.Errorf("failed to create SFTP server: %w", err)
		}
	}

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start API server in goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := server.Start(); err != nil {
			errChan <- err
		}
	}()

	// Start SFTP server in goroutine (if enabled)
	if sftpServer != nil {
		go func() {
			if err := sftpServer.Start(); err != nil {
				errChan <- fmt.Errorf("SFTP server error: %w", err)
			}
		}()
	}

	// Send heartbeat to panel after startup (in background to not block)
	go func() {
		// Give the API server a moment to start listening
		time.Sleep(500 * time.Millisecond)
		if err := server.SendHeartbeat(); err != nil {
			log.Warn("Failed to send startup heartbeat to panel", "error", err)
		}
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		log.Info("Received shutdown signal", "signal", sig)
	case err := <-errChan:
		return fmt.Errorf("server error: %w", err)
	}

	// Graceful shutdown
	log.Info("Shutting down...")
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Error("Shutdown error", "error", err)
	}

	if sftpServer != nil {
		if err := sftpServer.Stop(); err != nil {
			log.Error("SFTP shutdown error", "error", err)
		}
	}

	log.Info("Goodbye!")
	return nil
}
