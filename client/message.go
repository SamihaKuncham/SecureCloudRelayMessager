package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"securerelaymessager/logger"
	"securerelaymessager/security"
	"strings"
	"sync"
)

var msgForReplayVal string
var msgForTamperVal string

func MessageExchange(client *Clientele) {
	var wg sync.WaitGroup
	wg.Add(2)

	go sendMessage(client, &wg)
	go receiveMessage(client, &wg)

	wg.Wait()
	logger.Info("Closed connection to Relay")
}

// function to send an encrypted message to an authenticated client in an encrypted session
func sendMessage(client *Clientele, wg *sync.WaitGroup) {
	defer wg.Done()
	scanner := bufio.NewScanner(os.Stdin)
	for {
		select {
		case <-client.ctx.Done():
			logger.Info("sendMessage: shutting down")
			return
		default:
		}

		if !scanner.Scan() {
			// stdin closed (maybe Ctrl+D)
			client.cancelfn()
			return
		}

		text := scanner.Text()

		if client.session.sessionKey == nil {
			logger.Error("No session key made; no secure session established.")
			continue
		}

		if text == "REPLAY" || text == "TAMPER" {
			sendMaliciousPacket(client, text)
			continue
		}

		// Convert sessionKey into bytes (blocks)
		sharedKeyBytes := security.KeyToBytes(client.session.sessionKey)

		// Generate IV
		iv, err := security.GenerateIV(16)
		if err != nil {
			logger.Error("Error generating IV")
			return
		}

		// Create bitstream B & XOR text to get ciphertext
		msgBytes := []byte(text)
		bitstream := security.GenerateBitstream(sharedKeyBytes, iv, len(msgBytes))

		logger.Debugf("Bitstream generated (sender): %x", bitstream)
		ciphertext := security.XORBytes(msgBytes, bitstream)

		// update sequence number & put into bytes
		client.session.sequenceNumber++
		seqNumBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(seqNumBytes, client.session.sequenceNumber)

		sessionIDBytes := security.TimeToBytes(client.session.sessID)

		// compute MAC
		macString := append(iv, ciphertext...)
		macString = append(macString, sessionIDBytes...)
		macString = append(macString, seqNumBytes...)
		mac := security.ComputeMAC(sharedKeyBytes, macString)

		logger.Debugf("SENT MESSAGE PARTS:\n\tIV: %x\n\tCiphertext: %x\n\tMAC: %x\n\tSEQ_NUM: %x\n", iv, ciphertext, mac, seqNumBytes)

		// make payload = IV, C, MAC
		payload := append(iv, ciphertext...)
		payload = append(payload, mac...)
		// prep for transport w/ base64 encode
		payloadStr := base64.StdEncoding.EncodeToString(payload)

		// storing a message for replay
		if msgForReplayVal == "" {
			msgForReplayVal = payloadStr
		}
		// storing a message for tamper check
		if msgForTamperVal == "" {
			tamperPrefix := append([]byte(nil), payload[:16]...)
			tamperSuffix := append([]byte(nil), payload[len(payload)-32:]...)
			tamperedText := []byte("tampered")
			tamperedPacket := append(append(append([]byte{}, tamperPrefix...), tamperedText...), tamperSuffix...)
			msgForTamperVal = base64.StdEncoding.EncodeToString(tamperedPacket)
		}

		// send it out
		msg := fmt.Sprintf("MESSAGE %s %s %s\n", client.userId, client.peerId, payloadStr)
		err = client.sendText(msg)
		if err != nil {
			logger.Error("Error writing:", err)
			return
		}
	}
}

// Function to create malicious packets based on the first packet of the same communication session
func sendMaliciousPacket(client *Clientele, msgType string) {
	var msg string

	switch msgType {
	case "REPLAY":
		msg = fmt.Sprintf("MESSAGE %s %s %s\n", client.userId, client.peerId, msgForReplayVal)
	case "TAMPER":
		msg = fmt.Sprintf("MESSAGE %s %s %s\n", client.userId, client.peerId, msgForTamperVal)
	}
	err := client.sendText(msg)
	if err != nil {
		logger.Error("Error writing:", err)
		return
	}
}

// Parent function that handles received messages
func receiveMessage(client *Clientele, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-client.ctx.Done():
			logger.Info("receiveMessage: shutting down")
			return
		default:
		}
		msg, err := client.receiveText()
		if err != nil {
			logger.Error("Connection closed:", err)
			client.cancelfn()
			return
		}
		handleReceivedMessage(msg, client)
	}
}

/*
Method to handle incoming messages in an authenticated session
Replay attacks here are solved with the use of the session id and the sequence number of the message. With the receipt of each message, MAC changes since it depends on the session ID. This method only accepts messages if the MAC matches the message MAC and if the sequence number and session ID are correct.
In this way, session and sequence number verifications are implicitly done.
*/
func handleReceivedMessage(msg string, client *Clientele) {
	msg = strings.TrimSpace(msg)

	initParts := strings.SplitN(msg, " ", 6)
	if len(initParts) == 6 && initParts[0] == "INITS" {
		handlePeerSessionReinit(initParts, client)
		return
	}

	// Expected format: "MESSAGE currentNode peerNode msg"
	// Code for incoming session setup messages.
	parts := strings.SplitN(msg, " ", 4)
	if len(parts) != 4 || parts[0] != "MESSAGE" {
		if parts[0] == "INVRECV" {
			logger.Error("ERROR receiver is not available. Try again later.")
		} else {
			logger.Error("ERROR Invalid Message Received.", parts)
		}
		return
	}

	if parts[1] != client.peerId || parts[2] != client.userId {
		logger.Info("ERROR Incorrect Sender Receiver in Received Message")
		return
	} else {
		// TODO: validate message with session details. If no session setup, ignore the message
		logger.Debug(fmt.Sprintf("Received Encrypted Message from %s: %s", client.peerId, parts[3]))
	}

	// extract payload from parts
	encryptedPayload64 := parts[3]

	//decode base64
	encryptedBlob, err := base64.StdEncoding.DecodeString(encryptedPayload64)
	if err != nil {
		logger.Error("Error: decoding message payload:", err)
		return
	}

	// extract IV, C, & MAC from payload
	const ivSize = 16
	const macSize = 32
	if len(encryptedBlob) < ivSize+macSize {
		logger.Error("Error: message too short; invalid message")
	}
	iv := encryptedBlob[:ivSize]
	ciphertext := encryptedBlob[ivSize : len(encryptedBlob)-macSize]

	// Deep copy mac from encryptedBlob
	rawMacSlice := encryptedBlob[len(encryptedBlob)-macSize:]
	sender_mac := make([]byte, macSize)
	copy(sender_mac, rawMacSlice)

	// increment peer sequence number
	expectedSequenceNumber := client.session.peerSequenceNumber + 1
	seqNumBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqNumBytes, expectedSequenceNumber)

	logger.Debugf("RECEIVED MESSAGE PARTS:\n\tIV: %x\n\tCiphertext: %x\n\tMAC: %x\n\tSEQ_NUM: %x\n", iv, ciphertext, sender_mac, seqNumBytes)

	sessionIDBytes := security.TimeToBytes(client.session.sessID)

	// reconstruct macString = IV + C + SessID + SeqNum
	macString := append(iv, ciphertext...)
	macString = append(macString, sessionIDBytes...)
	macString = append(macString, seqNumBytes...)

	// verify MAC
	sharedKeyBytes := security.KeyToBytes(client.session.sessionKey)
	isValid := security.VerifyMAC(sharedKeyBytes, macString, sender_mac)
	if !isValid {
		logger.Error("Message MAC is invalid, dropping message")
		return
	}

	logger.Debug("Message MAC is valid. Decrypting and accepting message.")
	client.session.peerSequenceNumber = expectedSequenceNumber

	// decrypt ciphertext
	bitstream := security.GenerateBitstream(sharedKeyBytes, iv, len(ciphertext))
	logger.Debugf("XOR Bitstream generated: %x", bitstream)
	plainTextBytes := security.XORBytes(ciphertext, bitstream)
	plaintext := string(plainTextBytes)
	logger.Info(fmt.Sprintf("Received Message from %s: %s", client.peerId, plaintext))
}

func handlePeerSessionReinit(msgParts []string, client *Clientele) {
	if msgParts[1] != client.peerId || msgParts[2] != client.userId {
		logger.Warn("Ignoring INITS with mismatched sender/receiver", msgParts)
		return
	}

	logger.Warn("Peer requested session re-initialization. Rekeying current session.")
	handleInitMessage(msgParts, client)

	// Reply with local INITS so the reconnecting peer can complete its handshake.
	setInitMessage(client)
	sendInitializationMessage(client)

	logger.Info("Session re-initialization complete.")
}
