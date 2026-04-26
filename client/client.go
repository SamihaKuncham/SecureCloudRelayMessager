package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"securerelaymessager/logger"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

type Clientele struct {
	conn     *websocket.Conn
	userId   string
	peerId   string
	session  Session
	ctx      context.Context
	cancelfn context.CancelFunc
	writeMu  sync.Mutex
	pendingMu     sync.Mutex
	pendingFrames []string
}

type Session struct {
	sessID             time.Time
	sessionKey         *big.Int
	clientKey          *big.Int
	sequenceNumber     uint64
	peerSequenceNumber uint64
}

var Client Clientele

// Client driver program
func main() {
	enableDebug := flag.Bool("debug", false, "enable debug mode")
	flag.Parse()

	initClient(enableDebug)

	// Creating context to sync graceful shutdown
	Client.ctx, Client.cancelfn = context.WithCancel(context.Background())
	defer Client.cancelfn()

	// Creating a watchdog for graceful termination incase of relay or client death.
	go gracefulTermination()

	// Step1: Relay Registration
	RegisterWithRelay(&Client)
	ChoosePeerFromConnectedUsers(&Client)

	// Step2: Session Creation
	CreateClientSession(&Client)

	// Step3: Message Exchange
	MessageExchange(&Client)
}

// Function to initialize client parameters and setup connections to the relay.
func initClient(enableDebug *bool) {
	// Getting the username of the client for initialization
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter client username: ")
	username, _ := reader.ReadString('\n')
	Client.userId = strings.ToLower(strings.TrimSpace(username))
	if Client.userId == "" {
		panic("client username cannot be empty")
	}

	// Initializing the logger
	logger.Init(fmt.Sprintf("client-%s.log", Client.userId), *enableDebug)

	// Establish connection to relay
	var err error
	Client.conn, _, err = websocket.DefaultDialer.Dial("ws://localhost:9000/ws", nil)
	if err != nil {
		logger.Panic(err)
	}
}

// function to gracefully terminate all threads created on loss of connectivity
func gracefulTermination() {
	// Signal channel that notifies when we have a system termination
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	logger.Warn("Got termination signal:", sig)
	msg := fmt.Sprintf("TERM %s\n", Client.userId)

	// Informing Relay of termination
	err := Client.sendText(msg)
	if err != nil {
		logger.Warn("Error writing termination to Relay:", err)
	}
	Client.cancelfn()
	Client.conn.Close()

	// Close stdin to unblock sendMessage's scanner.Scan()
	logger.Info("closing stdin")
	if err := os.Stdin.Close(); err != nil {
		// usually "nil" or "use of closed file" if called twice; safe to ignore
		logger.Warn("Error closing stdin:", err)
	}
}

func (c *Clientele) sendText(message string) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn.WriteMessage(websocket.TextMessage, []byte(strings.TrimSpace(message)))
}

func (c *Clientele) receiveText() (string, error) {
	if pending, ok := c.popPendingFrame(); ok {
		return pending, nil
	}
	return c.receiveTextFromConn()
}


func (c *Clientele) receiveTextFromConn() (string, error) {
	_, payload, err := c.conn.ReadMessage()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(payload)), nil
}

func (c *Clientele) queuePendingFrame(frame string) {
	trimmed := strings.TrimSpace(frame)
	if trimmed == "" {
		return
	}
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	c.pendingFrames = append(c.pendingFrames, trimmed)
}

func (c *Clientele) popPendingFrame() (string, bool) {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	if len(c.pendingFrames) == 0 {
		return "", false
	}
	frame := c.pendingFrames[0]
	c.pendingFrames = c.pendingFrames[1:]
	return frame, true
}

func ChoosePeerFromConnectedUsers(client *Clientele) {
	reader := bufio.NewReader(os.Stdin)
	for {
		users, err := fetchConnectedUsers(client)
		if err != nil {
			logger.Error("Failed to fetch users list from relay:", err)
			fmt.Print("Press Enter to retry... ")
			_, _ = reader.ReadString('\n')
			continue
		}

		if len(users) == 0 {
			fmt.Println("No other connected users are currently available.")
			fmt.Print("Press Enter to refresh... ")
			_, _ = reader.ReadString('\n')
			continue
		}

		fmt.Println("Connected users:")
		for i, user := range users {
			fmt.Printf("%d. %s\n", i+1, user)
		}
		fmt.Print("Select peer by number (or type r to refresh): ")
		selectionRaw, _ := reader.ReadString('\n')
		selection := strings.ToLower(strings.TrimSpace(selectionRaw))

		if selection == "r" || selection == "" {
			continue
		}

		idx, err := strconv.Atoi(selection)
		if err != nil || idx < 1 || idx > len(users) {
			fmt.Println("Invalid selection.")
			continue
		}

		client.peerId = users[idx-1]
		logger.Info("Selected peer:", client.peerId)
		return
	}
}

func fetchConnectedUsers(client *Clientele) ([]string, error) {
	request := fmt.Sprintf("LIST %s", client.userId)
	if err := client.sendText(request); err != nil {
		return nil, err
	}

	for {
		// While waiting for USERS, read directly from socket so pending async
		// frames (e.g. INITS) are not re-consumed and re-queued in a loop.
		response, err := client.receiveTextFromConn()
		if err != nil {
			return nil, err
		}

		if response == "USERS" {
			return []string{}, nil
		}

		parts := strings.SplitN(response, " ", 2)
		if len(parts) == 2 && parts[0] == "USERS" {
			users := []string{}
			for _, username := range strings.Split(parts[1], ",") {
				trimmed := strings.TrimSpace(strings.ToLower(username))
				if trimmed == "" || trimmed == client.userId {
					continue
				}
				users = append(users, trimmed)
			}

			return users, nil
		}

		logger.Infof("Buffering asynchronous relay frame while waiting for USERS: %s", response)
		client.queuePendingFrame(response)
	}
}
