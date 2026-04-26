package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"path/filepath"
	"securerelaymessager/logger"
	"securerelaymessager/security"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

type Client struct {
	conn              *websocket.Conn
	sendToPeerChannel chan string
	PublicKey         *rsa.PublicKey
	isConnected       bool
	writeMu           sync.Mutex
}

var (
	clients         = map[string]*Client{}
	clientsMu       sync.RWMutex
	relayStore      = NewRelayStore()
	relayPrivateKey *rsa.PrivateKey
	relayPublicKey  *rsa.PublicKey
	upgrader        = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	// mu      sync.Mutex  <-- Can use this for when we implement adding multiple new clients
)

func main() {

	enableDebug := flag.Bool("debug", false, "enable debug mode")
	flag.Parse()
	logger.Init("relay.log", *enableDebug)

	var err error
	relayPrivateKey, err = security.LoadRSAPrivateKey("security/keys/relay_priv.pem")
	if err != nil {
		logger.Panic(err)
	}
	//relayPublicKey = &relayPrivateKey.PublicKey

	http.HandleFunc("/ws", handleWSClient)
	logger.Info("Relay websocket listening on ws://localhost:9000/ws")
	err = http.ListenAndServe(":9000", nil)
	if err != nil {
		logger.Panic(err)
	}
}

func handleWSClient(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Warn("Websocket upgrade failed:", err)
		return
	}
	go handleClient(conn)
}

// handling a new client by creating a connection vector and registering them
func handleClient(conn *websocket.Conn) {
	defer conn.Close()
	logger.Info("Client connected:", conn.RemoteAddr())

	line, err := readFrame(conn)
	if err != nil {
		logger.Error("Error reading:", err)
		return
	}
	line = strings.TrimSpace(line)

	// Expected format: "REGISTER username <base64(encryptedRc)> [pseudonym]"
	parts := strings.SplitN(line, " ", 4)
	if len(parts) < 3 || parts[0] != "REGISTER" {
		_ = writeFrame(conn, "ERROR Invalid Message Received")
		return
	}

	// Phase 1: Registration & Authentication
	username := strings.ToLower(parts[1]) // ensure username is lowercase as standard
	encryptedRcB64 := parts[2]
	pseudonym := username
	if len(parts) == 4 {
		pseudonym = strings.TrimSpace(parts[3])
		if pseudonym == "" {
			pseudonym = username
		}
	}
	if !registerClient(conn, username, pseudonym, encryptedRcB64) {
		return
	}

	// Setup to handle write and reads to the new client
	var wg sync.WaitGroup
	wg.Add(2)
	go WriteToClient(&wg, username)
	go ReadFromClient(&wg, username)
	flushBufferedMessages(username)

	wg.Wait()
	logger.Info("Terminating Client Connection:", username)
}

/*
 * Does the client authentication and registers the client with the relay. Registration here is process by
 * which the relay sets up a channel for communication to and from a client.
 */
func registerClient(conn *websocket.Conn, username, pseudonym, encryptedRcB64 string) bool {
	clientInfo, err := getOrCreateClient(username)
	if err != nil {
		_ = writeFrame(conn, "ERROR unknown_client")
		logger.Error("Unable to register unknown client:", username, "error:", err)
		return false
	}
	if clientInfo.PublicKey == nil {
		_ = writeFrame(conn, "ERROR missing_public_key")
		logger.Error("Client", username, "has nil public key")
		return false
	}

	encryptedRc, err := decodeBase64(encryptedRcB64)
	if err != nil {
		_ = writeFrame(conn, "ERROR bad_encoding")
		return false
	}

	// Decrypt Rc with relay's private key
	RcBytes, err := rsa.DecryptPKCS1v15(nil, relayPrivateKey, encryptedRc)
	if err != nil {
		_ = writeFrame(conn, "ERROR decrypt_failed")
		return false
	}
	Rc := string(RcBytes)

	// Generate Rr (relay nonce)
	Rr := generateNonce(16)

	// Build message {username, Rc, Rr}
	message := fmt.Sprintf("%s|%s|%s", username, Rc, Rr)

	// Encrypt with client’s public key
	encryptedResponse, err := rsa.EncryptPKCS1v15(rand.Reader, clientInfo.PublicKey, []byte(message))
	if err != nil {
		_ = writeFrame(conn, "ERROR encrypt_failed")
		logger.Error("client encryption failed!")
		return false
	}

	// Send base64 encoded response
	if err := writeFrame(conn, encodeBase64(encryptedResponse)); err != nil {
		logger.Error("Error sending relay challenge:", err)
		return false
	}

	// Step 3: Expect Rr in plaintext from client
	reply, err := readFrame(conn)
	if err != nil {
		logger.Info("Error reading Rr:", err)
		return false
	}
	reply = strings.TrimSpace(reply)

	if reply != Rr {
		_ = writeFrame(conn, "ERROR authentication_failed")
		logger.Error("Auth failed for", username)
		return false
	}

	// Success
	clientsMu.Lock()
	if clientInfo.isConnected {
		clientsMu.Unlock()
		_ = writeFrame(conn, "ERROR already_connected")
		logger.Warn("Duplicate login attempt for already connected client:", username)
		return false
	}
	clientInfo.conn = conn
	clientInfo.sendToPeerChannel = make(chan string, 10) // 10 buffer size to handle any backpressure
	clientInfo.isConnected = true
	clientsMu.Unlock()
	relayStore.SetPseudonym(username, pseudonym)
	if err := writeFrame(conn, "OK registration_successful"); err != nil {
		logger.Error("Error sending registration success to", username, ":", err)
		return false
	}
	logger.Info("Client", username, "authenticated successfully as pseudonym", relayStore.GetPseudonym(username))
	return true
}

/**********************
	Helper functions
***********************/

func generateNonce(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return encodeBase64(b)
}

func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func readFrame(conn *websocket.Conn) (string, error) {
	_, message, err := conn.ReadMessage()
	if err != nil {
		return "", err
	}
	return string(message), nil
}

func writeFrame(conn *websocket.Conn, payload string) error {
	return conn.WriteMessage(websocket.TextMessage, []byte(payload))
}

func getOrCreateClient(username string) (*Client, error) {
	clientsMu.RLock()
	clientInfo, ok := clients[username]
	clientsMu.RUnlock()
	if ok {
		if clientInfo.PublicKey == nil {
			if pubKey, exists := relayStore.GetPublicKey(username); exists {
				clientInfo.PublicKey = pubKey
			}
		}
		return clientInfo, nil
	}

	pubKey, exists := relayStore.GetPublicKey(username)
	if !exists {
		pubKeyPath := filepath.Join("security", "keys", fmt.Sprintf("%s_pub.pem", username))
		var err error
		pubKey, err = security.LoadRSAPublicKey(pubKeyPath)
		if err != nil {
			return nil, fmt.Errorf("error loading key for %s: %w", username, err)
		}
		relayStore.SetPublicKey(username, pubKey)
	}

	clientsMu.Lock()
	defer clientsMu.Unlock()
	if existing, exists := clients[username]; exists {
		if existing.PublicKey == nil {
			existing.PublicKey = pubKey
		}
		return existing, nil
	}
	clientInfo = &Client{PublicKey: pubKey, isConnected: false}
	clients[username] = clientInfo
	relayStore.SetPseudonym(username, username)
	return clientInfo, nil
}
