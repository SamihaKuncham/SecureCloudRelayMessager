package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Utility to generate relay and/or user RSA key pairs.
func main() {
	outDir := flag.String("out", "security/keys", "output directory for key files")
	user := flag.String("user", "", "username to generate keys for (creates <user>_priv.pem and <user>_pub.pem)")
	genRelay := flag.Bool("relay", false, "generate relay_priv.pem and relay_pub.pem")
	bits := flag.Int("bits", 2048, "RSA key size in bits")
	flag.Parse()

	if !*genRelay && strings.TrimSpace(*user) == "" {
		fmt.Println("No output requested. Use -relay and/or -user <username>.")
		os.Exit(1)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Println("Failed to create output directory:", err)
		os.Exit(1)
	}

	if *genRelay {
		if err := generatePair(*outDir, "relay", *bits); err != nil {
			fmt.Println("Failed to generate relay keys:", err)
			os.Exit(1)
		}
		fmt.Println("Generated relay keypair in", *outDir)
	}

	if strings.TrimSpace(*user) != "" {
		if err := generatePair(*outDir, strings.ToLower(strings.TrimSpace(*user)), *bits); err != nil {
			fmt.Println("Failed to generate user keys:", err)
			os.Exit(1)
		}
		fmt.Println("Generated user keypair for", strings.ToLower(strings.TrimSpace(*user)), "in", *outDir)
	}
}

func generatePair(outputDir string, name string, bits int) error {
	if bits < 2048 {
		return fmt.Errorf("key size %d is too small", bits)
	}

	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	if err := priv.Validate(); err != nil {
		return err
	}

	pub := &priv.PublicKey
	if pub.N.BitLen() != bits && bits >= 2048 {
		return fmt.Errorf("unexpected key size generated")
	}

	var privPath, pubPath string
	if name == "relay" {
		privPath = filepath.Join(outputDir, "relay_priv.pem")
		pubPath = filepath.Join(outputDir, "relay_pub.pem")
	} else {
		privPath = filepath.Join(outputDir, fmt.Sprintf("%s_priv.pem", name))
		pubPath = filepath.Join(outputDir, fmt.Sprintf("%s_pub.pem", name))
	}

	if err := writePrivateKey(privPath, priv); err != nil {
		return err
	}
	if err := writePublicKey(pubPath, pub); err != nil {
		return err
	}
	return nil
}

func writePrivateKey(path string, key *rsa.PrivateKey) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func writePublicKey(path string, pub crypto.PublicKey) error {
	pubBytes, _ := x509.MarshalPKIXPublicKey(pub)
	pubFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer pubFile.Close()

	return pem.Encode(pubFile, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
}
