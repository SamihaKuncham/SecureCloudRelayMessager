package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"securerelaymessager/logger"
	"securerelaymessager/security"
	"strings"
)

// Method to create client-relay session
func RegisterWithRelay(client *Clientele) {
	// Load relay's public key
	relayPubKey, err := security.LoadRSAPublicKey("security/keys/relay_pub.pem")
	if err != nil {
		logger.Panic("failed to load relay public key: " + err.Error())
	}

	// Generate Rc (client nonce)
	Rc := security.GenerateNonce(16)

	// Encrypt Rc with relay’s public key
	encryptedRc, err := rsa.EncryptPKCS1v15(rand.Reader, relayPubKey, []byte(Rc))
	if err != nil {
		logger.Panic("failed to encrypt Rc: " + err.Error())
	}

	encryptedRcB64 := base64.StdEncoding.EncodeToString(encryptedRc)

	// Send REGISTER message
	msg := fmt.Sprintf("REGISTER %s %s\n", client.userId, encryptedRcB64)
	if err := client.sendText(msg); err != nil {
		logger.Panic("failed to send register message: " + err.Error())
	}

	// Step 2: Receive relay’s encrypted message
	resp, err := client.receiveText()
	if err != nil {
		logger.Panic("failed to read response: " + err.Error())
	}

	// Decode Base64
	ciphertext, err := base64.StdEncoding.DecodeString(resp)
	if err != nil {
		logger.Panic("failed to decode base64: " + err.Error())
	}

	// Load client’s private key
	clientPrivKey, err := security.LoadRSAPrivateKey(fmt.Sprintf("security/keys/%s_priv.pem", client.userId))
	if err != nil {
		logger.Panic("failed to load client private key: " + err.Error())
	}

	// Decrypt the relay’s message
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, clientPrivKey, ciphertext)
	if err != nil {
		logger.Panic("failed to decrypt relay response: " + err.Error())
	}

	// Expect message format: username|Rc|Rr
	parts := strings.Split(string(plaintext), "|")
	if len(parts) != 3 {
		logger.Warn("Malformed relay response:", string(plaintext))
		return
	}
	recvUsername, recvRc, Rr := parts[0], parts[1], parts[2]

	if recvUsername != client.userId || recvRc != Rc {
		logger.Error("Authentication failed (nonce or username mismatch)")
		return
	}

	// Step 3: Send Rr back in plaintext
	if err := client.sendText(Rr + "\n"); err != nil {
		logger.Panic("failed to send relay nonce response: " + err.Error())
	}

	finalResp, err := client.receiveText()
	if err != nil {
		logger.Panic("failed to read registration confirmation: " + err.Error())
	}
	logger.Info("Relay:", finalResp)
}
