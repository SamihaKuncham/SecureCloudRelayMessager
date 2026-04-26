package security

import (
	"crypto/rand"
	"math/big"
	"os"
	"securerelaymessager/logger"
	"strings"
	"unicode"
)

var p *big.Int
var g = big.NewInt(2)
var secret *big.Int

// Prime number chosen is RFC 3526 (group number 16, 4096 bits)	the prime is stored in a separate file from an RFC dump.
// We do not calculate the prime since it is computationally wasteful, especially since the prime is well known.
func setPrime() {
	if p == nil || p.Sign() == 0 {
		logger.Info("Setting prime")

		data, err := os.ReadFile("security/prime")
		if err != nil {
			logger.Panic("Unable to find the prime number dump")
		}
		hexP := strings.Map(func(r rune) rune {
			if unicode.IsSpace(r) {
				return -1
			}
			return r
		}, string(data))

		tmpP := new(big.Int)
		if _, ok := tmpP.SetString(hexP, 16); !ok {
			logger.Panic("Failed to parse prime as hex")
			return
		}
		p = tmpP
	} else {
		logger.Info("Prime already known. Skipping...")
	}
}

// Int returns a uniform random value in [0, max). It panics if max <= 0, and returns an error if rand.Read returns one
func pickSecret() {
	if secret == nil {
		var err error
		secret, err = rand.Int(rand.Reader, p)
		if err != nil {
			logger.Panic("Unable to pick a secret.", err)
		}
		logger.Info("Client Secret Set.")
	} else {
		logger.Info("Client Secret known. Skipping...")
	}
}

// Uses internal fast modular exponentiation to pick the client side key (g^a mod p)
func PickClientKey() *big.Int {
	setPrime()
	pickSecret()
	return new(big.Int).Exp(g, secret, p)
}

func CalculateSharedKey(peerKey *big.Int) *big.Int {
	return new(big.Int).Exp(peerKey, secret, p)
}
