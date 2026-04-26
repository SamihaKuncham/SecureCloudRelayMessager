package security

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"securerelaymessager/logger"
	"time"
)

// BlockSize for the HMAC-based stream generation (SHA256 outputs 32 bytes)
const BlockSize = 32

// Helper: Load RSA private key
func LoadRSAPrivateKey(filename string) (*rsa.PrivateKey, error) {
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// Load RSA public key from PEM file
func LoadRSAPublicKey(filename string) (*rsa.PublicKey, error) {
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPub, nil
}

// Helper: Generate random base64 nonce
func GenerateNonce(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// Helper. Isn't currently used
func EncryptForRelay(relayPubKey *rsa.PublicKey, message string) string {
	// Encrypt Rc with relay’s public key
	encryptedRc, err := rsa.EncryptPKCS1v15(rand.Reader, relayPubKey, []byte(message))
	if err != nil {
		logger.Panic("failed to encrypt message: " + err.Error())
	}

	return base64.StdEncoding.EncodeToString(encryptedRc)
}

func GetDigitalSignature(username string, message string) string {
	clientPrivateKey, err := LoadRSAPrivateKey(fmt.Sprintf("security/keys/%s_priv.pem", username))
	if err != nil {
		logger.Panic("failed to load client private key for digital signature: " + err.Error())
	}
	hashedMessage := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, clientPrivateKey, crypto.SHA256, hashedMessage[:])
	if err != nil {
		logger.Panic("Unable to sign message", err)
	}
	return base64.StdEncoding.EncodeToString(signature)
}

func VerifyDigitalSignature(peerId string, message string, signatureStr string) bool {
	var signature []byte
	peerPublicKey, err := LoadRSAPublicKey(fmt.Sprintf("security/keys/%s_pub.pem", peerId))
	if err != nil {
		logger.Panic("failed to load client public key to verify signature: " + err.Error())
	}

	hashMessage := sha256.Sum256([]byte(message))
	signature, err = base64.StdEncoding.DecodeString(signatureStr)
	if err != nil {
		logger.Panic("Unable to decode signature string")
	}

	err = rsa.VerifyPKCS1v15(peerPublicKey, crypto.SHA256, hashMessage[:], signature)
	return err == nil
}

// Creates a random initialization vector of specified size
func GenerateIV(size int) ([]byte, error) {
	iv := make([]byte, size)
	_, err := rand.Read(iv)
	return iv, err
}

// Generates a stream of bytes to XOR against the message.
// It mimics the pseudocode: B[i] = HMAC(Key, IV + block_index)
// security.go/GenerateBitstream
func GenerateBitstream(key []byte, iv []byte, length int) []byte {
    keystream := make([]byte, 0, length+BlockSize)
    
    // Determine how many blocks we need
    numBlocks := (length + BlockSize - 1) / BlockSize

    for i := 0; i < numBlocks; i++ {
        // Create a counter for the block index
        counter := make([]byte, 4)
        binary.BigEndian.PutUint32(counter, uint32(i))

        ivCopy := make([]byte, len(iv))
        copy(ivCopy, iv) 
        
        data := append(ivCopy, counter...)
        
        // Generate block using HMAC
        block := ComputeHash(key, data)
        keystream = append(keystream, block...)
    }

    // Trim to exact message length
    return keystream[:length]
}

// XORBytes performs the encryption/decryption: Out[i] = In[i] ^ KeyStream[i]
// Revised security.go/XORBytes:
func XORBytes(input, keystream []byte) []byte {
    // The length check is assumed to be done by the caller (len(ciphertext) == len(bitstream)).
    if len(input) != len(keystream) {
        // Handle error if lengths don't match
        return nil // Or panic
    }
    
    // Create the output slice directly.
    output := make([]byte, len(input)) 
    
    // Perform the XOR directly onto the new output slice.
    for i := 0; i < len(input); i++ {
        output[i] = input[i] ^ keystream[i]
    }
    
    // Output is a brand new, correctly computed byte slice.
    return output
}

// ComputeMAC calculates the HMAC-SHA256
func ComputeMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyMAC compares calculated MAC with received MAC
func VerifyMAC(key, data, receivedMAC []byte) bool {
	expectedMAC := ComputeMAC(key, data)
	logger.Debug(fmt.Sprintf("receivedMAC=%x, expectedMAC=%x", receivedMAC, expectedMAC))
	return hmac.Equal(expectedMAC, receivedMAC)
}

// ComputeHash is a helper for the keystream generation
func ComputeHash(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// Helper to convert BigInt key to Bytes safely
func KeyToBytes(k *big.Int) []byte {
    // Ensure consistent byte length (e.g., 32 bytes for SHA256)
    return k.Bytes()
}

// Helper for converting time struct type to bytes
func TimeToBytes(t time.Time) []byte {
    // Convert the time to Unix nanoseconds (int64)
    // This is a fixed deterministic number regardless of timezone or struct internals
    unixNano := t.UnixNano()
    
    // Convert the int64 (8 bytes) into a fixed 8-byte array using BigEndian order
    b := make([]byte, 8)
    binary.BigEndian.PutUint64(b, uint64(unixNano))
    
    return b
}