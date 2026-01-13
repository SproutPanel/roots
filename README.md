# Roots

Roots is a game server daemon that manages Docker containers for game servers. It provides an HTTP/HTTPS API for server management, real-time console access via WebSocket, and SFTP file access.

## Building

```bash
# Build the binary
make build

# Or manually
go build -o roots ./cmd/roots

# Build with version info from git
make build-release

# Install to /usr/local/bin
sudo make install
```

## Configuration

Roots looks for configuration at `/etc/roots/config.yaml` by default. You can specify an alternative path with the `--config` flag.

### Interactive Setup

```bash
roots configure
```

This will prompt you for the essential settings and create the config file.

### Configuration File Format

```yaml
# Panel connection settings
panel:
  url: "https://panel.example.com"    # URL of the Sprout Panel (required)
  token: "your-api-token"             # API token for authentication (required)

# Daemon settings
daemon:
  host: "0.0.0.0"                     # Listen address (default: 0.0.0.0)
  port: 8443                          # Listen port (default: 8443)
  tls:
    enabled: false                    # Enable HTTPS (default: false)
    cert_file: "/etc/roots/cert.pem"  # Path to TLS certificate
    key_file: "/etc/roots/key.pem"    # Path to TLS private key

# Docker settings
docker:
  socket: "/var/run/docker.sock"      # Docker socket path (auto-detected)
  network: "roots_network"            # Docker network for containers (default: roots_network)

# Storage paths
storage:
  servers: "~/.local/share/roots/servers"  # Server data directory
  backups: "~/.local/share/roots/backups"  # Backup directory

# SFTP server settings
sftp:
  enabled: true                       # Enable SFTP server (default: true)
  port: 2022                          # SFTP port (default: 2022)
  host_key: "~/.config/roots/ssh_host_key"  # SSH host key path

# Resource limits for this node
resources:
  memory: "16GB"                      # Total memory available for servers
  disk: "100GB"                       # Total disk space available for servers
```

### Configuration Options Reference

#### `panel`

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `url` | string | Yes | `http://localhost:3000` | URL of the Sprout Panel |
| `token` | string | Yes | - | API token for panel authentication |

#### `daemon`

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `host` | string | No | `0.0.0.0` | IP address to listen on |
| `port` | int | No | `8443` | Port to listen on (1-65535) |

#### `daemon.tls`

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `enabled` | bool | No | `false` | Enable HTTPS |
| `cert_file` | string | If TLS enabled | - | Path to TLS certificate file |
| `key_file` | string | If TLS enabled | - | Path to TLS private key file |

#### `docker`

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `socket` | string | No | Auto-detected | Path to Docker socket |
| `network` | string | No | `roots_network` | Docker network name for containers |

The Docker socket is auto-detected:
- macOS: `~/.docker/run/docker.sock`
- Linux: `/var/run/docker.sock`

#### `storage`

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `servers` | string | No | `~/.local/share/roots/servers` | Directory for server data |
| `backups` | string | No | `~/.local/share/roots/backups` | Directory for backups |

Paths support `~` expansion for home directory.

#### `sftp`

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `enabled` | bool | No | `true` | Enable SFTP server |
| `port` | int | No | `2022` | SFTP port |
| `host_key` | string | No | `~/.config/roots/ssh_host_key` | Path to SSH host key |

The SSH host key is auto-generated on first run if it doesn't exist.

#### `resources`

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `memory` | string | No | - | Total memory limit for all servers |
| `disk` | string | No | - | Total disk limit for all servers |

Resource values support human-readable formats:
- Bytes: `1024`, `1024B`
- Kilobytes: `512K`, `512KB`
- Megabytes: `512M`, `512MB`
- Gigabytes: `16G`, `16GB`
- Terabytes: `1T`, `1TB`

## CLI Commands

### Daemon Management

```bash
# Start the daemon
roots run

# Start with custom config
roots run --config /path/to/config.yaml

# Check daemon status
roots status

# Watch status in real-time
roots status --watch

# Reload configuration without restart
roots reload

# Validate configuration
roots validate

# Run diagnostics
roots diagnostics
```

### Server Management

```bash
# List all servers
roots servers list

# Start a server (supports partial UUID)
roots servers start <uuid>

# Start all servers
roots servers start all

# Stop a server gracefully
roots servers stop <uuid>

# Stop all servers
roots servers stop all

# Restart a server
roots servers restart <uuid>

# Force kill a server
roots servers kill <uuid>

# Attach to server console
roots servers console <uuid>
```

### Updates

```bash
# Check for updates
roots update --check

# Update to the latest version
roots update

# Update without confirmation
roots update --force

# Use beta channel
roots update --channel beta
```

The update command:
- Fetches version info from the panel's `/api/releases/latest` endpoint
- Compares versions and shows changelog
- Downloads the new binary with checksum verification
- Creates a backup before replacing the current binary
- Works with both direct binaries and gzipped tarballs

## TLS/HTTPS Setup

### Using Let's Encrypt (recommended for production)

```bash
# Install certbot
sudo apt install certbot

# Get certificate
sudo certbot certonly --standalone -d daemon.example.com

# Update config
daemon:
  tls:
    enabled: true
    cert_file: /etc/letsencrypt/live/daemon.example.com/fullchain.pem
    key_file: /etc/letsencrypt/live/daemon.example.com/privkey.pem
```

### Using Self-Signed Certificate (development only)

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Update config
daemon:
  tls:
    enabled: true
    cert_file: /path/to/cert.pem
    key_file: /path/to/key.pem
```

Note: The CLI automatically allows self-signed certificates when connecting to localhost.

## API Endpoints

The daemon exposes a REST API for server management:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check (no auth) |
| GET | `/status` | Daemon status |
| POST | `/api/reload` | Reload configuration |
| GET | `/api/servers` | List all servers |
| POST | `/api/servers` | Create/install server |
| GET | `/api/servers/{uuid}` | Get server details |
| PUT | `/api/servers/{uuid}` | Update server |
| DELETE | `/api/servers/{uuid}` | Delete server |
| POST | `/api/servers/{uuid}/power` | Power actions (start/stop/restart/kill) |
| WS | `/api/servers/{uuid}/console` | Console WebSocket |
| WS | `/api/servers/{uuid}/stats` | Stats WebSocket |
| GET | `/api/servers/{uuid}/files` | List files |
| GET | `/api/servers/{uuid}/files/content` | Read file |
| PUT | `/api/servers/{uuid}/files/content` | Write file |
| GET | `/api/node/status` | Node resource stats |
| WS | `/api/node/stats` | Node stats WebSocket |

All endpoints except `/health` require authentication via Bearer token:
```
Authorization: Bearer <token>
```

For WebSocket connections, the token can be passed as a query parameter:
```
wss://daemon.example.com/api/servers/{uuid}/console?token=<token>
```

## Systemd Service

Create `/etc/systemd/system/roots.service`:

```ini
[Unit]
Description=Roots Game Server Daemon
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/usr/local/bin/roots run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable roots
sudo systemctl start roots
```
