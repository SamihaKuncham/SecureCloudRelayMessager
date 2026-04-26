package main

import (
	"fmt"
	"securerelaymessager/logger"
	"sort"
	"strings"
	"sync"
)

// Method forwards any messages present in the sendToPeer channel to the peer
func WriteToClient(wg *sync.WaitGroup, username string) {
	defer wg.Done()
	clientsMu.RLock()
	receiverInfo, ok := clients[username]
	clientsMu.RUnlock()
	if !ok || receiverInfo == nil {
		logger.Warn("WriteToClient: client metadata not found for", username)
		return
	}

	for msg := range receiverInfo.sendToPeerChannel {
		receiverInfo.writeMu.Lock()
		err := writeFrame(receiverInfo.conn, msg)
		receiverInfo.writeMu.Unlock()
		if err != nil {
			logger.Infof("Error writing to client %s. Error: %s\n", username, err)
			return
		}
	}
}

/*
This method reads messages from a client and forwards validates messages on to the intended receiver.
Note that the behavior of this method is a blocking one. If either the buffered reader or sendToReceiver channel is full, the method will block and not accept any more messages until full.
Changing this behavior requires the blocking model used to handle backpressure to be changed in all other similar functions in this package.
If incorrect messages or termination message is sent, the metadata is updated and this goroutine exits.
*/
func ReadFromClient(wg *sync.WaitGroup, senderID string) {
	defer wg.Done()
	clientsMu.RLock()
	senderInfo, ok := clients[senderID]
	clientsMu.RUnlock()
	if !ok || senderInfo == nil {
		logger.Warn("ReadFromClient: client metadata not found for", senderID)
		return
	}

	defer resetConnectionMetadata(senderID, senderInfo)

	for {
		msg, err := readFrame(senderInfo.conn)
		if err != nil {
			logger.Warn("Connection Closed:", err)
			return
		}
		msg = strings.TrimSpace(msg)
		if msg == "" {
			continue
		}

		msgParts := strings.SplitN(msg, " ", 4)
		msgType := msgParts[0]

		if msgType == "LIST" {
			if len(msgParts) != 2 || msgParts[1] != senderID {
				logger.Error("Malformed LIST message. Dropping message: ", msg)
				continue
			}
			handleListRequest(senderID, senderInfo)
			continue
		}

		if msgType == "TERM" {
			if len(msgParts) != 2 || msgParts[1] != senderID {
				logger.Error("Malformed TERM message. Dropping message: ", msg)
				continue
			}
			return
		}

		// Messages are of the form 'MSG_TYPE sender receiver content'
		if len(msgParts) < 3 {
			logger.Error("Malformed Message detected. Dropping message: ", msg)
			continue
		}

		// check if the message is spoofed
		if msgParts[1] != senderID {
			// Assuming a spoofed message. This message is dropped
			logger.Infof("ERROR Incorrect Sender Detected! Dropping this packet. message: %s, recUser:%s, expected:%s\n", msgParts, msgParts[1], senderID)
			continue
		}

		//Validating Message type
		if !validateMessageType(msgType) {
			logger.Error("Incorrect Message detected. Dropping message: ", msg)
			continue
		}
		logger.Info("Received Message ", msg)
		// handle messages based on their types
		switch msgType {
		case "MESSAGE":
			sendToPeer(senderInfo, msgParts[2], msg)
		case "INITS":
			sendToPeer(senderInfo, msgParts[2], msg)
		}
	}
}

func validateMessageType(msgType string) bool {
	return msgType == "MESSAGE" || msgType == "TERM" || msgType == "INITS" || msgType == "LIST"
}

// Done to recreate session metadata to accommadate a new session between clients
func resetConnectionMetadata(senderID string, senderInfo *Client) {
	logger.Warn(fmt.Sprintf("Detected client %s termination", senderID))
	clientsMu.Lock()
	defer clientsMu.Unlock()

	senderInfo.isConnected = false
	if senderInfo.sendToPeerChannel != nil {
		close(senderInfo.sendToPeerChannel)
	}
	senderInfo.conn = nil
	senderInfo.sendToPeerChannel = nil
}

// function to pass messages between client handlers in the relay
func sendToPeer(senderInfo *Client, peerId string, message string) {
	clientsMu.RLock()
	receiverInfo, ok := clients[peerId]
	clientsMu.RUnlock()

	if !ok || receiverInfo == nil || !receiverInfo.isConnected || receiverInfo.sendToPeerChannel == nil {
		logger.Warn("Client receiver not available. Generating error.")
		relayStore.BufferMessage(peerId, message)
		if senderInfo.sendToPeerChannel != nil {
			if !enqueueMessage(senderInfo.sendToPeerChannel, fmt.Sprintf("INVRECV %s Message:%s", peerId, message)) {
				logger.Warn("Unable to enqueue INVRECV error for sender")
			}
		}
	} else {
		if !enqueueMessage(receiverInfo.sendToPeerChannel, message) {
			logger.Warn("Unable to enqueue message to peer", peerId)
		}
	}
}

func enqueueMessage(ch chan string, message string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	ch <- message
	return true
}

func handleListRequest(senderID string, senderInfo *Client) {
	users := connectedUsersExcept(senderID)
	payload := "USERS"
	if len(users) > 0 {
		payload += " " + strings.Join(users, ",")
	}

	if senderInfo.sendToPeerChannel == nil || !enqueueMessage(senderInfo.sendToPeerChannel, payload) {
		logger.Warn("Unable to send USERS list to", senderID)
	}
}

func connectedUsersExcept(excludeUser string) []string {
	clientsMu.RLock()
	defer clientsMu.RUnlock()

	users := make([]string, 0, len(clients))
	for username, info := range clients {
		if username == excludeUser {
			continue
		}
		if info != nil && info.isConnected {
			users = append(users, username)
		}
	}

	sort.Strings(users)
	return users
}

func flushBufferedMessages(username string) {
	buffered := relayStore.DrainBufferedMessages(username)
	if len(buffered) == 0 {
		return
	}

	clientsMu.RLock()
	clientInfo, ok := clients[username]
	clientsMu.RUnlock()
	if !ok || clientInfo == nil || !clientInfo.isConnected || clientInfo.sendToPeerChannel == nil {
		for _, message := range buffered {
			relayStore.BufferMessage(username, message)
		}
		return
	}

	for _, message := range buffered {
		if !enqueueMessage(clientInfo.sendToPeerChannel, message) {
			logger.Warn("Unable to enqueue buffered message for", username)
			relayStore.BufferMessage(username, message)
		}
	}
	logger.Infof("Flushed %d buffered messages for %s", len(buffered), username)
}
