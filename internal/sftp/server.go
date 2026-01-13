package sftp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"
	"github.com/sproutpanel/roots/internal/config"
	"golang.org/x/crypto/ssh"
)

// Server represents an SFTP server
type Server struct {
	config   *config.Config
	logger   *slog.Logger
	listener net.Listener
	sshConfig *ssh.ServerConfig
}

// AuthResponse represents the response from the panel's SFTP auth endpoint
type AuthResponse struct {
	Allowed    bool   `json:"allowed"`
	ServerUUID string `json:"server_uuid"`
	Username   string `json:"username"`
	Error      string `json:"error"`
}

// NewServer creates a new SFTP server
func NewServer(cfg *config.Config, logger *slog.Logger) (*Server, error) {
	s := &Server{
		config: cfg,
		logger: logger,
	}

	// Load or generate host key
	hostKey, err := s.loadOrGenerateHostKey()
	if err != nil {
		return nil, fmt.Errorf("failed to load host key: %w", err)
	}

	// Configure SSH server
	s.sshConfig = &ssh.ServerConfig{
		PasswordCallback: s.passwordCallback,
	}
	s.sshConfig.AddHostKey(hostKey)

	return s, nil
}

// Start starts the SFTP server
func (s *Server) Start() error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.config.SFTP.Port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener

	s.logger.Info("SFTP server started", "address", addr)

	go s.acceptLoop()
	return nil
}

// Stop stops the SFTP server
func (s *Server) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// Check if server is shutting down
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			s.logger.Error("failed to accept connection", "error", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		s.logger.Debug("SSH handshake failed", "error", err, "remote", conn.RemoteAddr())
		return
	}
	defer sshConn.Close()

	s.logger.Info("SFTP connection established",
		"user", sshConn.User(),
		"remote", conn.RemoteAddr())

	// Discard global requests
	go ssh.DiscardRequests(reqs)

	// Handle channels
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			s.logger.Error("failed to accept channel", "error", err)
			continue
		}

		go s.handleChannel(channel, requests, sshConn.Permissions, sshConn.User())
	}
}

func (s *Server) handleChannel(channel ssh.Channel, requests <-chan *ssh.Request, permissions *ssh.Permissions, username string) {
	defer channel.Close()

	for req := range requests {
		if req.Type != "subsystem" {
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}

		// Check if subsystem is sftp
		if len(req.Payload) < 4 {
			req.Reply(false, nil)
			continue
		}
		subsystemLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
		if subsystemLen+4 > len(req.Payload) {
			req.Reply(false, nil)
			continue
		}
		subsystem := string(req.Payload[4 : 4+subsystemLen])

		if subsystem != "sftp" {
			req.Reply(false, nil)
			continue
		}

		req.Reply(true, nil)

		// Get server UUID from connection permissions
		serverUUID := permissions.Extensions["server_uuid"]
		if serverUUID == "" {
			s.logger.Error("no server UUID in connection permissions")
			return
		}

		// Create SFTP server with root at server directory
		serverDir := filepath.Join(s.config.Storage.Servers, serverUUID)

		// Ensure directory exists
		if _, err := os.Stat(serverDir); os.IsNotExist(err) {
			s.logger.Error("server directory does not exist", "path", serverDir)
			return
		}

		// Create SFTP server handlers
		handler := &sftpHandler{
			root:   serverDir,
			logger: s.logger,
		}

		server := sftp.NewRequestServer(channel, sftp.Handlers{
			FileGet:  handler,
			FilePut:  handler,
			FileCmd:  handler,
			FileList: handler,
		})

		s.logger.Info("SFTP session started",
			"user", username,
			"server", serverUUID,
			"root", serverDir)

		if err := server.Serve(); err != nil && err != io.EOF {
			s.logger.Error("SFTP server error", "error", err)
		}

		s.logger.Info("SFTP session ended", "user", username, "server", serverUUID)
		return
	}
}

func (s *Server) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	username := conn.User()

	// Authenticate against panel API
	authResp, err := s.authenticateWithPanel(username, string(password))
	if err != nil {
		s.logger.Error("panel auth request failed", "error", err, "user", username)
		return nil, fmt.Errorf("authentication failed")
	}

	if !authResp.Allowed {
		s.logger.Info("SFTP auth rejected", "user", username, "error", authResp.Error)
		return nil, fmt.Errorf("authentication failed")
	}

	s.logger.Info("SFTP auth success", "user", username, "server", authResp.ServerUUID)

	// Return permissions with server UUID for later use
	return &ssh.Permissions{
		Extensions: map[string]string{
			"server_uuid": authResp.ServerUUID,
			"username":    authResp.Username,
		},
	}, nil
}

func (s *Server) authenticateWithPanel(username, password string) (*AuthResponse, error) {
	url := fmt.Sprintf("%s/api/internal/sftp/auth", s.config.Panel.URL)

	body, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.config.Panel.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, err
	}

	return &authResp, nil
}

func (s *Server) loadOrGenerateHostKey() (ssh.Signer, error) {
	keyPath := s.config.SFTP.HostKey

	// Try to load existing key
	keyData, err := os.ReadFile(keyPath)
	if err == nil {
		signer, err := ssh.ParsePrivateKey(keyData)
		if err == nil {
			s.logger.Info("loaded SSH host key", "path", keyPath)
			return signer, nil
		}
		s.logger.Warn("failed to parse existing host key, generating new one", "error", err)
	}

	// Generate new key
	s.logger.Info("generating new SSH host key", "path", keyPath)

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode private key to PEM
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	// Write key to file
	if err := os.WriteFile(keyPath, privateKeyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to write host key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated key: %w", err)
	}

	return signer, nil
}

// sftpHandler implements SFTP request handlers with directory jailing
type sftpHandler struct {
	root   string
	logger *slog.Logger
}

// resolvePath resolves a path within the jailed root
func (h *sftpHandler) resolvePath(requestPath string) (string, error) {
	// Clean and join path
	cleaned := filepath.Clean("/" + requestPath)
	fullPath := filepath.Join(h.root, cleaned)

	// Ensure it's still within root (prevent directory traversal)
	absRoot, _ := filepath.Abs(h.root)
	absPath, _ := filepath.Abs(fullPath)

	if !strings.HasPrefix(absPath, absRoot) {
		return "", fmt.Errorf("path outside root: %s", requestPath)
	}

	return fullPath, nil
}

// Fileread handles file read requests
func (h *sftpHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	path, err := h.resolvePath(r.Filepath)
	if err != nil {
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, sftp.ErrSSHFxNoSuchFile
		}
		return nil, sftp.ErrSSHFxFailure
	}

	return file, nil
}

// Filewrite handles file write requests
func (h *sftpHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	path, err := h.resolvePath(r.Filepath)
	if err != nil {
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	// Create parent directory if needed
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, sftp.ErrSSHFxFailure
	}

	// Default to truncate on write
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC

	file, err := os.OpenFile(path, flags, 0644)
	if err != nil {
		return nil, sftp.ErrSSHFxFailure
	}

	return file, nil
}

// Filecmd handles file commands (remove, rename, mkdir, etc.)
func (h *sftpHandler) Filecmd(r *sftp.Request) error {
	path, err := h.resolvePath(r.Filepath)
	if err != nil {
		return sftp.ErrSSHFxPermissionDenied
	}

	switch r.Method {
	case "Remove":
		return os.Remove(path)
	case "Rmdir":
		return os.RemoveAll(path)
	case "Mkdir":
		return os.MkdirAll(path, 0755)
	case "Rename":
		newPath, err := h.resolvePath(r.Target)
		if err != nil {
			return sftp.ErrSSHFxPermissionDenied
		}
		return os.Rename(path, newPath)
	case "Symlink":
		// Disallow symlinks for security
		return sftp.ErrSSHFxPermissionDenied
	case "Setstat":
		// Handle chmod/chown - just return success for now
		return nil
	}

	return sftp.ErrSSHFxOpUnsupported
}

// Filelist handles directory listing and stat requests
func (h *sftpHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	path, err := h.resolvePath(r.Filepath)
	if err != nil {
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	switch r.Method {
	case "List":
		entries, err := os.ReadDir(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, sftp.ErrSSHFxNoSuchFile
			}
			return nil, sftp.ErrSSHFxFailure
		}

		infos := make([]os.FileInfo, 0, len(entries))
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			infos = append(infos, info)
		}
		return listerat(infos), nil

	case "Stat":
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, sftp.ErrSSHFxNoSuchFile
			}
			return nil, sftp.ErrSSHFxFailure
		}
		return listerat([]os.FileInfo{info}), nil

	case "Readlink":
		// Disallow reading symlinks
		return nil, sftp.ErrSSHFxPermissionDenied
	}

	return nil, sftp.ErrSSHFxOpUnsupported
}

// listerat implements sftp.ListerAt
type listerat []os.FileInfo

func (l listerat) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(ls, l[offset:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}
