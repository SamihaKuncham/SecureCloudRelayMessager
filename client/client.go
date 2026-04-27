package main

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"securerelaymessager/logger"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

type Clientele struct {
	conn          *websocket.Conn
	userId        string
	peerId        string
	session       Session
	ctx           context.Context
	cancelfn      context.CancelFunc
	writeMu       sync.Mutex
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

func initClientWithParams(username, relayURL string, debug bool) error {
	Client.userId = strings.ToLower(strings.TrimSpace(username))
	if Client.userId == "" {
		return fmt.Errorf("username cannot be empty")
	}
	logger.Init(fmt.Sprintf("client-%s.log", Client.userId), debug)

	var err error
	Client.conn, _, err = websocket.DefaultDialer.Dial(relayURL, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to relay: %w", err)
	}

	Client.ctx, Client.cancelfn = context.WithCancel(context.Background())
	go gracefulTermination()
	return nil
}

func gracefulTermination() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Warn("Got termination signal:", sig)
	if err := Client.sendText(fmt.Sprintf("TERM %s", Client.userId)); err != nil {
		logger.Warn("Error writing termination to Relay:", err)
	}
	Client.cancelfn()
	Client.conn.Close()
	fyneApp.Quit()
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

func fetchConnectedUsers(client *Clientele) ([]string, error) {
	request := fmt.Sprintf("LIST %s", client.userId)
	if err := client.sendText(request); err != nil {
		return nil, err
	}

	for {
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
