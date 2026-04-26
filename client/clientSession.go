package main

import (
	"fmt"
	"math/big"
	"securerelaymessager/logger"
	"securerelaymessager/security"
	"strings"
	"time"
)

var initializationMessage string

// Function to setup authenticated session between two clients
func CreateClientSession(client *Clientele) {
	// 1. Initialize session metadata
	// 1.2. generate the session id
	client.session.sessID = security.PickSessionID(client.session.sessID)
	// 1.1. generate the secret
	client.session.clientKey = security.PickClientKey()

	setInitMessage(client)

	// channel to signal that initialization is done
	done := make(chan struct{})

	// 2. Wait for the session initialization message from the peer
	go func() {
		defer close(done) // signal completion
		receiveInitializationMessage(client)
	}()

	// 3. Send the session initialization to the peer. If not available, resend on reception
	sendInitializationMessage(client)

	// 4. Block until receiveInitializationMessage returns
	<-done

}

// Sets the initialization message as a global variable
func setInitMessage(client *Clientele) {
	// Message of the form "INITS senderID peerID SessID clientSecretKey signature(sessID+secret)"
	stringSessID := client.session.sessID.Format(time.RFC3339)
	stringClientSecretKey := client.session.clientKey.Text(16)
	signature := security.GetDigitalSignature(client.userId, stringSessID+stringClientSecretKey)
	initializationMessage = fmt.Sprintf("INITS %s %s %s %s %s\n", client.userId, client.peerId, stringSessID, stringClientSecretKey, signature)
}

// Function to send initialization message
func sendInitializationMessage(client *Clientele) {
	logger.Info("Sending Initialization message to relay")
	err := client.sendText(initializationMessage)
	if err != nil {
		logger.Panic("Error Writing Initialization Message. ", err)
		return
	}
}

// function to handle initialization message and setup a session
func receiveInitializationMessage(client *Clientele) {
	var msgParts []string
	retransmitInitMessage := false
	for {
		select {
		case <-client.ctx.Done():
			logger.Info("receiveInitializationMessage: shutting down")
			return
		default:
		}

		msg, err := client.receiveText()
		if err != nil {
			logger.Error("Connection closed:", err)
			client.cancelfn()
			return
		}
		logger.Info("\nGot msg: \n", msg)
		msgParts = strings.SplitN(strings.TrimSpace(msg), " ", 6)
		if msgParts[0] == "INITS" && msgParts[1] == client.peerId {
			// Detected an initialization message
			logger.Info("Detected receiver session initialization")
			break
		} else if msgParts[0] == "INVRECV" {
			// Unable to find receiver
			logger.Warn("Unable to find receiver for session initialization. Holding off retry.")
			retransmitInitMessage = true
		}
	}
	if retransmitInitMessage {
		sendInitializationMessage(client)
	} else {
		logger.Debug("retransmit is not set!")
	}
	handleInitMessage(msgParts, client)
	logger.Info("Session Initialization Complete\n ===================================SESSION===================================")
}

// Assumes that the initialization message has reached and handles it
func handleInitMessage(msgParts []string, client *Clientele) {
	isSignatureSecure := security.VerifyDigitalSignature(client.peerId, msgParts[3]+msgParts[4], msgParts[5])
	if !isSignatureSecure {
		logger.Panic("Signature has been manipulated! Exiting...")
		return
	}

	// converting sessionID and key back into required formats
	peerSessID, err := time.Parse(time.RFC3339, msgParts[3])
	if err != nil {
		logger.Panic("Cannot convert sessionID.", err)
	}

	peerSecretKey := new(big.Int)
	peerSecretKey.SetString(msgParts[4], 16)

	// Setting the shared session key
	logger.Info("Setting shared session key and session ID.")
	client.session.sessionKey = security.CalculateSharedKey(peerSecretKey)

	var chosenSessID time.Time
	if peerSessID.After(client.session.sessID) {
		chosenSessID = peerSessID
		logger.Debugf("Chose peer's session ID: %s", chosenSessID.Format(time.RFC3339))
	} else {
		chosenSessID = client.session.sessID
		logger.Debugf("Kept client's session ID: %s", chosenSessID.Format(time.RFC3339))
	}
	client.session.sessID = chosenSessID.Truncate(time.Second)

	logger.Debugf("DEBUG SESS_ID: client.session.sessID=%x, peerSessID=%x", client.session.sessID, peerSessID)

	// Setting sequence numbers
	client.session.sequenceNumber = 0
	client.session.peerSequenceNumber = 0

	logger.Info("Session key, ID, and sequence numbers initialized.")
}
