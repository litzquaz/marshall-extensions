// Marshall Honeypot System
// Adaptive deception system for detecting and analyzing malicious extensions
// Part of the NullSec Security Suite

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// ThreatLevel indicates the severity of detected threat
type ThreatLevel int

const (
	ThreatNone ThreatLevel = iota
	ThreatLow
	ThreatMedium
	ThreatHigh
	ThreatCritical
)

// HoneypotType defines different deception strategies
type HoneypotType string

const (
	// NetworkHoneypot - fake network services
	NetworkHoneypot HoneypotType = "network"
	// DataHoneypot - fake sensitive data
	DataHoneypot HoneypotType = "data"
	// APIHoneypot - fake API responses
	APIHoneypot HoneypotType = "api"
	// FileHoneypot - fake file system
	FileHoneypot HoneypotType = "file"
)

// ThreatEvent represents detected malicious activity
type ThreatEvent struct {
	ID           string      `json:"id"`
	Timestamp    time.Time   `json:"timestamp"`
	ExtensionID  string      `json:"extension_id"`
	ThreatType   string      `json:"threat_type"`
	ThreatLevel  ThreatLevel `json:"threat_level"`
	Description  string      `json:"description"`
	SourceIP     string      `json:"source_ip,omitempty"`
	Payload      []byte      `json:"payload,omitempty"`
	Fingerprint  string      `json:"fingerprint"`
}

// HoneypotConfig configures a honeypot instance
type HoneypotConfig struct {
	Type           HoneypotType `json:"type"`
	Port           int          `json:"port,omitempty"`
	ResponseDelay  time.Duration `json:"response_delay"`
	FakeData       interface{}  `json:"fake_data,omitempty"`
	LogInteraction bool         `json:"log_interaction"`
}

// HoneypotManager manages all honeypot instances
type HoneypotManager struct {
	mu          sync.RWMutex
	honeypots   map[string]*Honeypot
	events      []ThreatEvent
	eventChan   chan ThreatEvent
	socketPath  string
	running     bool
}

// Honeypot represents a single deception instance
type Honeypot struct {
	ID       string
	Config   HoneypotConfig
	Active   bool
	Triggers int
	Created  time.Time
	manager  *HoneypotManager
}

// NewHoneypotManager creates a new manager
func NewHoneypotManager(socketPath string) *HoneypotManager {
	return &HoneypotManager{
		honeypots:  make(map[string]*Honeypot),
		events:     make([]ThreatEvent, 0, 1000),
		eventChan:  make(chan ThreatEvent, 100),
		socketPath: socketPath,
	}
}

// Start initializes the honeypot system
func (m *HoneypotManager) Start() error {
	m.mu.Lock()
	m.running = true
	m.mu.Unlock()

	// Start event processor
	go m.processEvents()

	// Start IPC listener for sandbox communication
	go m.listenIPC()

	// Spawn default honeypots
	m.spawnDefaultHoneypots()

	log.Println("[HONEYPOT] System started")
	return nil
}

// spawnDefaultHoneypots creates standard deception traps
func (m *HoneypotManager) spawnDefaultHoneypots() {
	// Fake API endpoints
	m.SpawnHoneypot(HoneypotConfig{
		Type:           APIHoneypot,
		ResponseDelay:  100 * time.Millisecond,
		LogInteraction: true,
		FakeData: map[string]interface{}{
			"/api/credentials": map[string]string{
				"admin_password": "fake_password_123",
				"api_key":        "sk_fake_1234567890",
			},
			"/api/users": []map[string]string{
				{"username": "admin", "email": "admin@fake.local"},
				{"username": "root", "email": "root@fake.local"},
			},
		},
	})

	// Fake network services
	m.SpawnHoneypot(HoneypotConfig{
		Type:           NetworkHoneypot,
		Port:           8888, // Fake debug port
		ResponseDelay:  50 * time.Millisecond,
		LogInteraction: true,
	})

	// Fake sensitive files
	m.SpawnHoneypot(HoneypotConfig{
		Type:           FileHoneypot,
		LogInteraction: true,
		FakeData: map[string]string{
			"/etc/shadow":      "root:$6$fake$hash:19000:0:99999:7:::",
			"~/.ssh/id_rsa":    "-----BEGIN FAKE PRIVATE KEY-----\n...",
			"~/.aws/credentials": "[default]\naws_access_key_id=AKIAFAKE\n",
		},
	})

	// Fake data honeytokens
	m.SpawnHoneypot(HoneypotConfig{
		Type:           DataHoneypot,
		LogInteraction: true,
		FakeData: map[string]interface{}{
			"credit_cards": []string{
				"4111-1111-1111-1111", // Known test card
				"5500-0000-0000-0004",
			},
			"ssn": []string{
				"000-00-0000", // Invalid SSN format used as token
			},
		},
	})
}

// SpawnHoneypot creates a new honeypot instance
func (m *HoneypotManager) SpawnHoneypot(config HoneypotConfig) (*Honeypot, error) {
	id := generateID()
	
	honeypot := &Honeypot{
		ID:      id,
		Config:  config,
		Active:  true,
		Created: time.Now(),
		manager: m,
	}

	m.mu.Lock()
	m.honeypots[id] = honeypot
	m.mu.Unlock()

	// Start network listener if applicable
	if config.Type == NetworkHoneypot && config.Port > 0 {
		go honeypot.startNetworkListener()
	}

	log.Printf("[HONEYPOT] Spawned %s honeypot: %s", config.Type, id)
	return honeypot, nil
}

// startNetworkListener creates a fake network service
func (h *Honeypot) startNetworkListener() {
	addr := fmt.Sprintf("127.0.0.1:%d", h.Config.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[HONEYPOT] Failed to start listener: %v", err)
		return
	}
	defer listener.Close()

	log.Printf("[HONEYPOT] Network honeypot listening on %s", addr)

	for h.Active {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go h.handleConnection(conn)
	}
}

// handleConnection processes incoming honeypot connections
func (h *Honeypot) handleConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	h.Triggers++

	// Read incoming data
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)

	// Log the threat event
	event := ThreatEvent{
		ID:          generateID(),
		Timestamp:   time.Now(),
		ThreatType:  "honeypot_trigger",
		ThreatLevel: ThreatHigh,
		Description: fmt.Sprintf("Connection to honeypot service on port %d", h.Config.Port),
		SourceIP:    remoteAddr,
		Payload:     buf[:n],
		Fingerprint: generateFingerprint(buf[:n]),
	}

	h.manager.eventChan <- event

	// Respond with deceptive data after delay
	time.Sleep(h.Config.ResponseDelay)
	
	// Send fake response to gather more intel
	fakeResponse := []byte("SSH-2.0-OpenSSH_8.0\r\n")
	conn.Write(fakeResponse)
}

// HandleAPIRequest processes fake API requests from sandbox
func (m *HoneypotManager) HandleAPIRequest(extensionID, api string, payload []byte) []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Find appropriate API honeypot
	for _, hp := range m.honeypots {
		if hp.Config.Type == APIHoneypot && hp.Active {
			hp.Triggers++

			// Log event
			event := ThreatEvent{
				ID:          generateID(),
				Timestamp:   time.Now(),
				ExtensionID: extensionID,
				ThreatType:  "suspicious_api_call",
				ThreatLevel: ThreatMedium,
				Description: fmt.Sprintf("Extension made suspicious API call: %s", api),
				Payload:     payload,
				Fingerprint: generateFingerprint(payload),
			}
			m.eventChan <- event

			// Return fake data based on API
			if data, ok := hp.Config.FakeData.(map[string]interface{}); ok {
				if fakeResp, exists := data[api]; exists {
					jsonData, _ := json.Marshal(fakeResp)
					return jsonData
				}
			}
		}
	}

	// Default fake response
	return []byte(`{"status":"ok","data":[]}`)
}

// HandleFileRequest returns fake file content
func (m *HoneypotManager) HandleFileRequest(extensionID, path string) []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, hp := range m.honeypots {
		if hp.Config.Type == FileHoneypot && hp.Active {
			hp.Triggers++

			// Critical alert for sensitive file access
			event := ThreatEvent{
				ID:          generateID(),
				Timestamp:   time.Now(),
				ExtensionID: extensionID,
				ThreatType:  "sensitive_file_access",
				ThreatLevel: ThreatCritical,
				Description: fmt.Sprintf("Extension attempted to read: %s", path),
				Fingerprint: extensionID + ":" + path,
			}
			m.eventChan <- event

			// Return fake content
			if data, ok := hp.Config.FakeData.(map[string]string); ok {
				if content, exists := data[path]; exists {
					return []byte(content)
				}
			}
		}
	}

	return nil
}

// processEvents handles incoming threat events
func (m *HoneypotManager) processEvents() {
	for event := range m.eventChan {
		m.mu.Lock()
		m.events = append(m.events, event)
		
		// Trim old events (keep last 1000)
		if len(m.events) > 1000 {
			m.events = m.events[len(m.events)-1000:]
		}
		m.mu.Unlock()

		// Log event
		log.Printf("[THREAT] Level=%d Type=%s Extension=%s: %s",
			event.ThreatLevel, event.ThreatType, event.ExtensionID, event.Description)

		// Escalate critical threats
		if event.ThreatLevel >= ThreatCritical {
			m.escalateThreat(event)
		}
	}
}

// escalateThreat handles critical threats
func (m *HoneypotManager) escalateThreat(event ThreatEvent) {
	log.Printf("[CRITICAL] Escalating threat from extension %s", event.ExtensionID)
	
	// In production:
	// 1. Notify Marshall to quarantine extension
	// 2. Save forensic data
	// 3. Block similar patterns
	// 4. Alert user
}

// listenIPC listens for sandbox communication
func (m *HoneypotManager) listenIPC() {
	// Remove existing socket
	os.Remove(m.socketPath)

	listener, err := net.Listen("unix", m.socketPath)
	if err != nil {
		log.Printf("[HONEYPOT] IPC error: %v", err)
		return
	}
	defer listener.Close()

	log.Printf("[HONEYPOT] IPC listening on %s", m.socketPath)

	for m.running {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go m.handleIPCConnection(conn)
	}
}

// handleIPCConnection processes sandbox messages
func (m *HoneypotManager) handleIPCConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var msg struct {
		Type        string `json:"type"`
		ExtensionID string `json:"extension_id"`
		API         string `json:"api"`
		Path        string `json:"path"`
		Payload     []byte `json:"payload"`
	}

	if err := decoder.Decode(&msg); err != nil {
		return
	}

	var response []byte

	switch msg.Type {
	case "api_request":
		response = m.HandleAPIRequest(msg.ExtensionID, msg.API, msg.Payload)
	case "file_request":
		response = m.HandleFileRequest(msg.ExtensionID, msg.Path)
	case "threat_alert":
		// Received threat from sandbox
		event := ThreatEvent{
			ID:          generateID(),
			Timestamp:   time.Now(),
			ExtensionID: msg.ExtensionID,
			ThreatType:  msg.API,
			ThreatLevel: ThreatHigh,
			Payload:     msg.Payload,
		}
		m.eventChan <- event
		response = []byte(`{"status":"received"}`)
	}

	encoder.Encode(map[string]interface{}{
		"success": true,
		"data":    response,
	})
}

// GetThreatReport returns recent threat events
func (m *HoneypotManager) GetThreatReport() []ThreatEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	// Return copy
	events := make([]ThreatEvent, len(m.events))
	copy(events, m.events)
	return events
}

// Stop shuts down the honeypot system
func (m *HoneypotManager) Stop() {
	m.mu.Lock()
	m.running = false
	
	for _, hp := range m.honeypots {
		hp.Active = false
	}
	m.mu.Unlock()

	close(m.eventChan)
	os.Remove(m.socketPath)
	log.Println("[HONEYPOT] System stopped")
}

// Helper functions
func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateFingerprint(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	// Simple fingerprint - in production use proper hashing
	b := make([]byte, 16)
	for i, d := range data {
		b[i%16] ^= d
	}
	return hex.EncodeToString(b)
}

func main() {
	socketPath := "/tmp/marshall-honeypot.sock"
	if len(os.Args) > 1 {
		socketPath = os.Args[1]
	}

	manager := NewHoneypotManager(socketPath)
	
	if err := manager.Start(); err != nil {
		log.Fatalf("Failed to start honeypot: %v", err)
	}

	// Keep running
	select {}
}
