package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"securerelaymessager/logger"
	"securerelaymessager/security"
	"strings"
	"sync"
)

var (
	outgoingCh      = make(chan string, 10)
	onMessage       func(from, text string)
	msgForReplayVal string
	msgForTamperVal string
)

func MessageExchange(client *Clientele) {
	var wg sync.WaitGroup
	wg.Add(2)
	go sendMessage(client, &wg)
	go receiveMessage(client, &wg)
	wg.Wait()
	logger.Info("Closed connection to Relay")
}

func sendMessage(client *Clientele, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-client.ctx.Done():
			logger.Info("sendMessage: shutting down")
			return
		case text := <-outgoingCh:
			if client.session.sessionKey == nil {
				logger.Error("No session key made; no secure session established.")
				continue
			}

			if text == "REPLAY" || text == "TAMPER" {
				sendMaliciousPacket(client, text)
				continue
			}

			sharedKeyBytes := security.KeyToBytes(client.session.sessionKey)

			iv, err := security.GenerateIV(16)
			if err != nil {
				logger.Error("Error generating IV")
				return
			}

			msgBytes := []byte(text)
			bitstream := security.GenerateBitstream(sharedKeyBytes, iv, len(msgBytes))
			logger.Debugf("Bitstream generated (sender): %x", bitstream)
			ciphertext := security.XORBytes(msgBytes, bitstream)

			client.session.sequenceNumber++
			seqNumBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(seqNumBytes, client.session.sequenceNumber)
			sessionIDBytes := security.TimeToBytes(client.session.sessID)

			macString := append(iv, ciphertext...)
			macString = append(macString, sessionIDBytes...)
			macString = append(macString, seqNumBytes...)
			mac := security.ComputeMAC(sharedKeyBytes, macString)

			logger.Debugf("SENT MESSAGE PARTS:\n\tIV: %x\n\tCiphertext: %x\n\tMAC: %x\n\tSEQ_NUM: %x\n", iv, ciphertext, mac, seqNumBytes)

			payload := append(iv, ciphertext...)
			payload = append(payload, mac...)
			payloadStr := base64.StdEncoding.EncodeToString(payload)

			if msgForReplayVal == "" {
				msgForReplayVal = payloadStr
			}
			if msgForTamperVal == "" {
				tamperPrefix := append([]byte(nil), payload[:16]...)
				tamperSuffix := append([]byte(nil), payload[len(payload)-32:]...)
				tamperedText := []byte("tampered")
				tamperedPacket := append(append(append([]byte{}, tamperPrefix...), tamperedText...), tamperSuffix...)
				msgForTamperVal = base64.StdEncoding.EncodeToString(tamperedPacket)
			}

			msg := fmt.Sprintf("MESSAGE %s %s %s", client.userId, client.peerId, payloadStr)
			if err := client.sendText(msg); err != nil {
				logger.Error("Error writing:", err)
				return
			}
		}
	}
}

func sendMaliciousPacket(client *Clientele, msgType string) {
	var msg string
	switch msgType {
	case "REPLAY":
		msg = fmt.Sprintf("MESSAGE %s %s %s", client.userId, client.peerId, msgForReplayVal)
	case "TAMPER":
		msg = fmt.Sprintf("MESSAGE %s %s %s", client.userId, client.peerId, msgForTamperVal)
	}
	if err := client.sendText(msg); err != nil {
		logger.Error("Error writing:", err)
	}
}

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

func handleReceivedMessage(msg string, client *Clientele) {
	msg = strings.TrimSpace(msg)

	initParts := strings.SplitN(msg, " ", 6)
	if len(initParts) == 6 && initParts[0] == "INITS" {
		handlePeerSessionReinit(initParts, client)
		return
	}

	parts := strings.SplitN(msg, " ", 4)
	if len(parts) != 4 || parts[0] != "MESSAGE" {
		if len(parts) > 0 && parts[0] == "INVRECV" {
			logger.Error("ERROR receiver is not available. Try again later.")
			if onMessage != nil {
				onMessage("System", "Peer is not available. Try again later.")
			}
		} else {
			logger.Error("ERROR Invalid Message Received.", parts)
		}
		return
	}

	if parts[1] != client.peerId || parts[2] != client.userId {
		logger.Info("ERROR Incorrect Sender Receiver in Received Message")
		return
	}

	logger.Debug(fmt.Sprintf("Received Encrypted Message from %s: %s", client.peerId, parts[3]))

	encryptedBlob, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		logger.Error("Error: decoding message payload:", err)
		return
	}

	const ivSize = 16
	const macSize = 32
	if len(encryptedBlob) < ivSize+macSize {
		logger.Error("Error: message too short; invalid message")
		return
	}
	iv := encryptedBlob[:ivSize]
	ciphertext := encryptedBlob[ivSize : len(encryptedBlob)-macSize]

	senderMAC := make([]byte, macSize)
	copy(senderMAC, encryptedBlob[len(encryptedBlob)-macSize:])

	expectedSequenceNumber := client.session.peerSequenceNumber + 1
	seqNumBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqNumBytes, expectedSequenceNumber)

	logger.Debugf("RECEIVED MESSAGE PARTS:\n\tIV: %x\n\tCiphertext: %x\n\tMAC: %x\n\tSEQ_NUM: %x\n", iv, ciphertext, senderMAC, seqNumBytes)

	sessionIDBytes := security.TimeToBytes(client.session.sessID)
	macString := append(iv, ciphertext...)
	macString = append(macString, sessionIDBytes...)
	macString = append(macString, seqNumBytes...)

	sharedKeyBytes := security.KeyToBytes(client.session.sessionKey)
	if !security.VerifyMAC(sharedKeyBytes, macString, senderMAC) {
		logger.Error("Message MAC is invalid, dropping message")
		if onMessage != nil {
			onMessage("System", "⚠ Received message with invalid MAC — dropped")
		}
		return
	}

	logger.Debug("Message MAC is valid. Decrypting and accepting message.")
	client.session.peerSequenceNumber = expectedSequenceNumber

	bitstream := security.GenerateBitstream(sharedKeyBytes, iv, len(ciphertext))
	logger.Debugf("XOR Bitstream generated: %x", bitstream)
	plaintext := string(security.XORBytes(ciphertext, bitstream))

	logger.Info(fmt.Sprintf("Received Message from %s: %s", client.peerId, plaintext))
	if onMessage != nil {
		onMessage(client.peerId, plaintext)
	}
}

func handlePeerSessionReinit(msgParts []string, client *Clientele) {
	if msgParts[1] != client.peerId || msgParts[2] != client.userId {
		logger.Warn("Ignoring INITS with mismatched sender/receiver", msgParts)
		return
	}
	logger.Warn("Peer requested session re-initialization. Rekeying current session.")
	handleInitMessage(msgParts, client)
	setInitMessage(client)
	sendInitializationMessage(client)
	logger.Info("Session re-initialization complete.")
}
