# Let's Encrypt Auto TLS Implementation Plan (CertMagic)

## Overview

Use [CertMagic](https://github.com/caddyserver/certmagic) - the library that powers Caddy's automatic HTTPS. CertMagic provides:
- HTTP-01, TLS-ALPN-01, and DNS-01 challenge support
- Automatic certificate renewal (starts 30 days before expiry)
- OCSP stapling
- Robust error handling and retry logic
- Optional DNS provider integration (Cloudflare, Route53, etc.)

## Files to Modify/Create

| File | Changes |
|------|---------|
| `cmd/roots/main.go` | Add auto-TLS CLI flags to `run` command |
| `internal/tls/autotls.go` | NEW: CertMagic wrapper and configuration |
| `internal/tls/dns_providers.go` | NEW: DNS provider factory for DNS-01 challenges |
| `internal/api/server.go` | Add CertMagic TLS config integration |
| `internal/config/config.go` | Add `AutoTLS` config section |
| `internal/logger/banner.go` | Update banner to show TLS mode |
| `go.mod` | Add CertMagic and DNS provider dependencies |

---

## CLI Flags

```
roots run --auto-tls --tls-hostname node1.example.com

FLAGS:
  --auto-tls              Enable automatic TLS via Let's Encrypt
  --tls-hostname string   FQDN for the certificate (required with --auto-tls)
  --tls-staging           Use Let's Encrypt staging CA (for testing)
  --tls-email string      Email for Let's Encrypt account notifications
  --dns-provider string   DNS provider for DNS-01 challenge (cloudflare, route53)
```

**Validation Rules:**
- `--auto-tls` requires `--tls-hostname`
- `--tls-hostname` must be a valid FQDN (not IP, not localhost)
- `--dns-provider` is optional; if not set, uses HTTP-01 challenge
- Mutually exclusive with manual TLS (`--auto-tls` cannot be used with `daemon.tls.enabled: true`)

---

## Configuration Schema

```yaml
# ~/.config/roots/config.yaml

daemon:
  host: 0.0.0.0
  port: 8443
  tls:
    enabled: false       # Manual TLS - mutually exclusive with auto_tls
    cert_file: ""
    key_file: ""

auto_tls:
  enabled: false         # Can be enabled via config or --auto-tls flag
  hostname: ""           # FQDN for certificate
  email: ""              # Email for Let's Encrypt (recommended)
  staging: false         # Use staging CA for testing
  cache_dir: ""          # Default: ~/.config/roots/certs
  dns_provider: ""       # Optional: cloudflare, route53
  dns_credentials:       # Provider-specific credentials
    api_token: ""        # Cloudflare API token
    # Or for AWS:
    # access_key_id: ""
    # secret_access_key: ""
    # region: ""
```

**Defaults:**
```go
AutoTLS: AutoTLSConfig{
    Enabled:  false,
    CacheDir: filepath.Join(home, ".config", "roots", "certs"),
    Staging:  false,
}
```

---

## Implementation Details

### 1. Config Types (`internal/config/config.go`)

```go
type Config struct {
    // ... existing fields ...
    AutoTLS AutoTLSConfig `yaml:"auto_tls"`
}

type AutoTLSConfig struct {
    Enabled        bool              `yaml:"enabled"`
    Hostname       string            `yaml:"hostname"`
    Email          string            `yaml:"email"`
    Staging        bool              `yaml:"staging"`
    CacheDir       string            `yaml:"cache_dir"`
    DNSProvider    string            `yaml:"dns_provider"`
    DNSCredentials map[string]string `yaml:"dns_credentials"`
}

// Validate checks auto_tls configuration
func (c *AutoTLSConfig) Validate() error {
    if !c.Enabled {
        return nil
    }

    if c.Hostname == "" {
        return fmt.Errorf("auto_tls.hostname is required when auto_tls is enabled")
    }

    // Validate hostname format (FQDN, not IP)
    if net.ParseIP(c.Hostname) != nil {
        return fmt.Errorf("auto_tls.hostname must be a domain name, not an IP address")
    }

    if c.Hostname == "localhost" {
        return fmt.Errorf("auto_tls.hostname cannot be localhost")
    }

    // Validate DNS provider if specified
    if c.DNSProvider != "" {
        validProviders := []string{"cloudflare", "route53"}
        if !slices.Contains(validProviders, c.DNSProvider) {
            return fmt.Errorf("invalid dns_provider: %s (valid: %v)", c.DNSProvider, validProviders)
        }
    }

    return nil
}
```

### 2. AutoTLS Manager (`internal/tls/autotls.go`)

```go
package tls

import (
    "context"
    "crypto/tls"
    "fmt"
    "log/slog"
    "net/http"
    "time"

    "github.com/caddyserver/certmagic"
)

type AutoTLSManager struct {
    config      *certmagic.Config
    hostname    string
    httpServer  *http.Server  // For HTTP-01 challenge on port 80
    logger      *slog.Logger
}

type AutoTLSOptions struct {
    Hostname       string
    Email          string
    CacheDir       string
    Staging        bool
    DNSProvider    string
    DNSCredentials map[string]string
    Logger         *slog.Logger
}

func NewAutoTLSManager(opts AutoTLSOptions) (*AutoTLSManager, error) {
    // Ensure cache directory exists
    if err := os.MkdirAll(opts.CacheDir, 0700); err != nil {
        return nil, fmt.Errorf("failed to create cert cache directory: %w", err)
    }

    // Configure storage
    storage := &certmagic.FileStorage{Path: opts.CacheDir}

    // Create config
    cfg := certmagic.NewDefault()
    cfg.Storage = storage
    cfg.DefaultServerName = opts.Hostname

    // Set email if provided
    if opts.Email != "" {
        cfg.Email = opts.Email
    }

    // Use staging CA for testing
    if opts.Staging {
        cfg.CA = certmagic.LetsEncryptStagingCA
        opts.Logger.Warn("Using Let's Encrypt STAGING CA - certificates will not be trusted!")
    }

    // Configure DNS-01 solver if provider specified
    if opts.DNSProvider != "" {
        solver, err := NewDNSSolver(opts.DNSProvider, opts.DNSCredentials)
        if err != nil {
            return nil, fmt.Errorf("failed to configure DNS provider: %w", err)
        }
        cfg.DNS01Solver = solver
        opts.Logger.Info("Using DNS-01 challenge", "provider", opts.DNSProvider)
    }

    // Set up event callbacks for logging
    cfg.OnEvent = func(ctx context.Context, event string, data map[string]any) error {
        switch event {
        case "cert_obtaining":
            opts.Logger.Info("Obtaining certificate", "hostname", data["identifier"])
        case "cert_obtained":
            opts.Logger.Info("Certificate obtained successfully", "hostname", data["identifier"])
        case "cert_renewed":
            opts.Logger.Info("Certificate renewed", "hostname", data["identifier"])
        case "cert_failed":
            opts.Logger.Error("Certificate acquisition failed", "hostname", data["identifier"], "error", data["error"])
        }
        return nil
    }

    return &AutoTLSManager{
        config:   cfg,
        hostname: opts.Hostname,
        logger:   opts.Logger,
    }, nil
}

// ObtainCertificate pre-fetches the certificate synchronously
// This is called at startup to ensure we have a valid cert before accepting connections
func (m *AutoTLSManager) ObtainCertificate(ctx context.Context) error {
    m.logger.Info("Obtaining TLS certificate", "hostname", m.hostname)

    // Use a timeout context for initial cert acquisition
    acquireCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
    defer cancel()

    if err := m.config.ManageSync(acquireCtx, []string{m.hostname}); err != nil {
        return fmt.Errorf("failed to obtain certificate for %s: %w", m.hostname, err)
    }

    m.logger.Info("TLS certificate ready", "hostname", m.hostname)
    return nil
}

// TLSConfig returns the TLS configuration for the HTTPS server
func (m *AutoTLSManager) TLSConfig() *tls.Config {
    tlsConfig := m.config.TLSConfig()
    tlsConfig.NextProtos = []string{"h2", "http/1.1"} // Enable HTTP/2
    return tlsConfig
}

// StartHTTPChallengeServer starts the HTTP-01 challenge server on port 80
// Only needed if not using DNS-01 challenge
func (m *AutoTLSManager) StartHTTPChallengeServer(ctx context.Context) error {
    m.httpServer = &http.Server{
        Addr:         ":80",
        Handler:      m.config.HTTPChallengeHandler(http.HandlerFunc(redirectToHTTPS)),
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 10 * time.Second,
    }

    go func() {
        m.logger.Info("Starting HTTP challenge server", "address", ":80")
        if err := m.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            m.logger.Error("HTTP challenge server error", "error", err)
        }
    }()

    // Shutdown when context is cancelled
    go func() {
        <-ctx.Done()
        shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        m.httpServer.Shutdown(shutdownCtx)
    }()

    return nil
}

// StopHTTPChallengeServer stops the HTTP-01 challenge server
func (m *AutoTLSManager) StopHTTPChallengeServer() error {
    if m.httpServer != nil {
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        return m.httpServer.Shutdown(ctx)
    }
    return nil
}

// redirectToHTTPS redirects HTTP requests to HTTPS (except ACME challenges)
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
    target := "https://" + r.Host + r.URL.RequestURI()
    http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// CertInfo returns information about the current certificate
func (m *AutoTLSManager) CertInfo() (*CertificateInfo, error) {
    certs := m.config.AllMatchingCertificates(m.hostname)
    if len(certs) == 0 {
        return nil, fmt.Errorf("no certificate found for %s", m.hostname)
    }

    cert := certs[0]
    return &CertificateInfo{
        Hostname:  m.hostname,
        NotBefore: cert.Leaf.NotBefore,
        NotAfter:  cert.Leaf.NotAfter,
        Issuer:    cert.Leaf.Issuer.CommonName,
    }, nil
}

type CertificateInfo struct {
    Hostname  string    `json:"hostname"`
    NotBefore time.Time `json:"not_before"`
    NotAfter  time.Time `json:"not_after"`
    Issuer    string    `json:"issuer"`
}
```

### 3. DNS Provider Factory (`internal/tls/dns_providers.go`)

```go
package tls

import (
    "fmt"

    "github.com/caddyserver/certmagic"
    "github.com/libdns/cloudflare"
    "github.com/libdns/route53"
)

// NewDNSSolver creates a DNS-01 solver for the specified provider
func NewDNSSolver(provider string, credentials map[string]string) (*certmagic.DNS01Solver, error) {
    var dnsProvider certmagic.ACMEDNSProvider

    switch provider {
    case "cloudflare":
        apiToken := credentials["api_token"]
        if apiToken == "" {
            return nil, fmt.Errorf("cloudflare requires dns_credentials.api_token")
        }
        dnsProvider = &cloudflare.Provider{
            APIToken: apiToken,
        }

    case "route53":
        dnsProvider = &route53.Provider{
            AccessKeyId:     credentials["access_key_id"],
            SecretAccessKey: credentials["secret_access_key"],
            Region:          credentials["region"],
            // If empty, uses AWS SDK default credential chain (IAM role, env vars, etc.)
        }

    default:
        return nil, fmt.Errorf("unsupported DNS provider: %s", provider)
    }

    return &certmagic.DNS01Solver{
        DNSProvider: dnsProvider,
    }, nil
}
```

### 4. Update Main Entry Point (`cmd/roots/main.go`)

```go
func runCmd() *cobra.Command {
    var (
        autoTLS      bool
        tlsHostname  string
        tlsStaging   bool
        tlsEmail     string
        dnsProvider  string
    )

    cmd := &cobra.Command{
        Use:   "run",
        Short: "Start the Roots daemon",
        PreRunE: func(cmd *cobra.Command, args []string) error {
            // Validate auto-TLS flags
            if autoTLS {
                if tlsHostname == "" {
                    return fmt.Errorf("--tls-hostname is required when using --auto-tls")
                }
                // Validate hostname
                if net.ParseIP(tlsHostname) != nil {
                    return fmt.Errorf("--tls-hostname must be a domain name, not an IP address")
                }
                if tlsHostname == "localhost" {
                    return fmt.Errorf("--tls-hostname cannot be localhost (Let's Encrypt requires a public domain)")
                }
            }
            return nil
        },
        RunE: func(cmd *cobra.Command, args []string) error {
            return runDaemon(RunOptions{
                AutoTLS:     autoTLS,
                TLSHostname: tlsHostname,
                TLSStaging:  tlsStaging,
                TLSEmail:    tlsEmail,
                DNSProvider: dnsProvider,
            })
        },
    }

    cmd.Flags().BoolVar(&autoTLS, "auto-tls", false, "Enable automatic TLS via Let's Encrypt")
    cmd.Flags().StringVar(&tlsHostname, "tls-hostname", "", "FQDN for the TLS certificate (required with --auto-tls)")
    cmd.Flags().BoolVar(&tlsStaging, "tls-staging", false, "Use Let's Encrypt staging CA (for testing)")
    cmd.Flags().StringVar(&tlsEmail, "tls-email", "", "Email for Let's Encrypt account notifications")
    cmd.Flags().StringVar(&dnsProvider, "dns-provider", "", "DNS provider for DNS-01 challenge (cloudflare, route53)")

    return cmd
}

type RunOptions struct {
    AutoTLS     bool
    TLSHostname string
    TLSStaging  bool
    TLSEmail    string
    DNSProvider string
}

func runDaemon(opts RunOptions) error {
    // ... existing setup code ...

    // Merge CLI flags with config (CLI takes precedence)
    if opts.AutoTLS {
        cfg.AutoTLS.Enabled = true
        cfg.AutoTLS.Hostname = opts.TLSHostname
        cfg.AutoTLS.Staging = opts.TLSStaging
        if opts.TLSEmail != "" {
            cfg.AutoTLS.Email = opts.TLSEmail
        }
        if opts.DNSProvider != "" {
            cfg.AutoTLS.DNSProvider = opts.DNSProvider
        }
    }

    // Validate mutual exclusivity
    if cfg.Daemon.TLS.Enabled && cfg.AutoTLS.Enabled {
        return fmt.Errorf("cannot use both manual TLS (daemon.tls.enabled) and auto-TLS simultaneously")
    }

    // ... Docker client setup ...

    // Setup TLS if auto-TLS enabled
    var autoTLSManager *tls.AutoTLSManager
    if cfg.AutoTLS.Enabled {
        var err error
        autoTLSManager, err = tls.NewAutoTLSManager(tls.AutoTLSOptions{
            Hostname:       cfg.AutoTLS.Hostname,
            Email:          cfg.AutoTLS.Email,
            CacheDir:       cfg.AutoTLS.CacheDir,
            Staging:        cfg.AutoTLS.Staging,
            DNSProvider:    cfg.AutoTLS.DNSProvider,
            DNSCredentials: cfg.AutoTLS.DNSCredentials,
            Logger:         log,
        })
        if err != nil {
            return fmt.Errorf("failed to initialize auto-TLS: %w", err)
        }

        // Obtain certificate before starting server
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
        if err := autoTLSManager.ObtainCertificate(ctx); err != nil {
            cancel()
            return fmt.Errorf("failed to obtain TLS certificate: %w", err)
        }
        cancel()

        // Start HTTP challenge server if not using DNS-01
        if cfg.AutoTLS.DNSProvider == "" {
            if err := autoTLSManager.StartHTTPChallengeServer(context.Background()); err != nil {
                return fmt.Errorf("failed to start HTTP challenge server: %w", err)
            }
            defer autoTLSManager.StopHTTPChallengeServer()
        }
    }

    // ... banner, server creation ...

    // Start API server
    go func() {
        var err error
        if autoTLSManager != nil {
            err = server.StartWithAutoTLS(autoTLSManager)
        } else {
            err = server.Start()
        }
        if err != nil {
            errChan <- err
        }
    }()

    // ... rest of daemon ...
}
```

### 5. Update API Server (`internal/api/server.go`)

```go
import (
    rootstls "github.com/sproutpanel/roots/internal/tls"
)

// StartWithAutoTLS starts the server with CertMagic auto-TLS
func (s *Server) StartWithAutoTLS(autoTLS *rootstls.AutoTLSManager) error {
    addr := fmt.Sprintf("%s:%d", s.config.Daemon.Host, s.config.Daemon.Port)

    s.httpServer = &http.Server{
        Addr:         addr,
        Handler:      s.router,
        TLSConfig:    autoTLS.TLSConfig(),
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 5 * time.Minute,
        IdleTimeout:  120 * time.Second,
    }

    s.logger.Info("Starting API server with auto-TLS", "address", addr)

    // ListenAndServeTLS with empty cert/key paths uses TLSConfig.GetCertificate
    return s.httpServer.ListenAndServeTLS("", "")
}

// GetTLSMode returns the current TLS mode for status endpoint
func (s *Server) GetTLSMode() string {
    if s.autoTLS != nil {
        return "auto-tls"
    }
    if s.config.TLSEnabled() {
        return "manual"
    }
    return "disabled"
}
```

### 6. Update Banner (`internal/logger/banner.go`)

```go
type BannerConfig struct {
    Version     string
    APIAddress  string
    SFTPAddress string
    SFTPEnabled bool
    DockerPath  string
    PanelURL    string
    TLSMode     string  // NEW: "auto-tls", "manual", "disabled"
    TLSHostname string  // NEW: hostname for auto-tls
}

// In PrintBanner():
if cfg.TLSMode == "auto-tls" {
    fmt.Fprintf(w, "       TLS: %s (auto-TLS: %s)\n", green("enabled"), cfg.TLSHostname)
} else if cfg.TLSMode == "manual" {
    fmt.Fprintf(w, "       TLS: %s (manual)\n", green("enabled"))
} else {
    fmt.Fprintf(w, "       TLS: %s\n", yellow("disabled"))
}
```

---

## Error Handling & Fallback Behavior

### Startup Failures

| Scenario | Behavior |
|----------|----------|
| Invalid hostname | Exit with error: "hostname must be a valid FQDN" |
| Port 80 in use (HTTP-01) | Exit with error: "port 80 required for ACME challenge" |
| DNS provider misconfigured | Exit with error: "failed to configure DNS provider: ..." |
| Certificate acquisition fails | Exit with error after 5 min timeout |
| Cache directory not writable | Exit with error: "failed to create cert cache" |

### Runtime Failures

| Scenario | Behavior |
|----------|----------|
| Certificate renewal fails | CertMagic retries with exponential backoff (built-in) |
| DNS provider API error | Logged, retries automatically |
| OCSP stapling fails | Falls back to no stapling (transparent to clients) |

### Graceful Degradation

```go
// In ObtainCertificate():
if err := m.config.ManageSync(ctx, []string{m.hostname}); err != nil {
    // Check if we have a cached cert that's still valid
    certs := m.config.AllMatchingCertificates(m.hostname)
    if len(certs) > 0 && time.Now().Before(certs[0].Leaf.NotAfter) {
        m.logger.Warn("Failed to renew certificate, using cached cert",
            "error", err,
            "expires", certs[0].Leaf.NotAfter,
        )
        return nil  // Continue with cached cert
    }
    return err  // No valid cached cert, must fail
}
```

---

## Testing Strategy

### 1. Unit Tests
- Hostname validation
- Config parsing
- DNS provider factory

### 2. Integration Tests (Staging CA)

```bash
# Test with staging CA (no rate limits)
roots run --auto-tls --tls-hostname test.example.com --tls-staging

# Verify cert is from staging
curl -v https://test.example.com:8443/health
# Should show: issuer: (STAGING) Ersatz Autograph X1
```

### 3. DNS-01 Testing

```bash
# With Cloudflare
export CF_API_TOKEN="..."
roots run --auto-tls --tls-hostname test.example.com --dns-provider cloudflare
```

---

## Dependencies

```bash
go get github.com/caddyserver/certmagic
go get github.com/libdns/cloudflare  # Optional: for Cloudflare DNS-01
go get github.com/libdns/route53     # Optional: for AWS Route53 DNS-01
```

---

## Security Considerations

1. **Cache directory permissions**: Created with `0700` (owner only)
2. **DNS credentials**: Should not be logged; marked as sensitive in config
3. **ACME account key**: Stored in cache directory, protected by filesystem permissions
4. **HTTP-01 redirect**: All non-ACME HTTP requests redirected to HTTPS
