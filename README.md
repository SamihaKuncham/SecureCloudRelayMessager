# SecureCloudRelayMessager

A secure client–relay–client messaging system implemented in **Go**, designed to provide **mutual authentication**, **end-to-end confidentiality**, **message integrity**, and **forward secrecy** over an untrusted relay using Hashes for encryption.

This project implements a custom cryptographic protocol combining **public-key authentication**, **Diffie–Hellman key exchange**, and **HMAC-based authenticated encryption**.

## Features

- Mutual authentication between clients and relay using challenge–response
- End-to-end encrypted client-to-client communication
- Perfect Forward Secrecy using ephemeral Diffie–Hellman keys
- Message integrity and authenticity using HMAC
- Replay-attack protection via session IDs and message sequence numbers
- Debug logging support for both relay and clients
- All **client ↔ relay** communication is encrypted using long-term **public** keys
- **Client ↔ client** messages are encrypted using a session key unknown to the relay

## How to Run

#### Prerequisites
This project requires Go **1.20**+

#### Steps

0. (Optional) Generate key pairs for relay and users:
   `go run ./security/generate_keys --relay`
   `go run ./security/generate_keys --user alice`
   `go run ./security/generate_keys --user bob`

   Repeat `--user <username>` for every additional client.

1. Start the relay server:
   `go run ./relay`
2. Start the client using
   `go run ./client`
3. Enter a client username when prompted.
4. After registration, the client requests a list of connected users from the relay and shows selectable peers.
5. Select a peer from the list. Once both clients have selected each other, session setup starts automatically.

   *User keys must exist as* `security/keys/<username>_priv.pem` *and* `security/keys/<username>_pub.pem`.

6. Users can start typing messages at each client at this point.

   *Add --debug to the above commands to create debug logs.*

## Protocol Summary

#### Phase **1**: Registration & Mutual Authentication

- Public-key based challenge–response using nonces
- Ensures both relay and clients verify each other’s identity
- Prevents spoofing and replay attacks

#### Phase **2**: Secure Session Setup

- Clients establish a shared session key using Diffie–Hellman
- Key exchange messages are digitally signed
- Ephemeral secrets are deleted after session key derivation

#### Phase **3**: Secure Message Exchange

- Messages encrypted using an HMAC-derived keystream
- Each message contains the following contents:
   - Random IV
   - Ciphertext
   - HMAC over `(IV || ciphertext || sessionID || sequenceNumber)`

- Message sequence numbers prevent replay attacks

## Potential Improvements

* Use different keys for HMAC and encryption. Currently using the same key for convenience.
