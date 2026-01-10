package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

type SSHState struct {
	encrypter cipher.Stream
	decrypter cipher.Stream
	macWriter hash.Hash
	macReader hash.Hash
	writeSeq  uint32 // Counter for packets we SEND
	readSeq   uint32 // Counter for packets we RECEIVE
	sessionId []byte // RFC 4253: exchange hash used as session identifier
}

func activateEncryption(kBytes, hBytes []byte) (*SSHState, error) {
	// For the initial handshake, SessionID is identical to the Exchange Hash (H)
	sessionId := hBytes

	// RFC 4253 Definitions:
	// 'A' = Initial IV client to server
	// 'B' = Initial IV server to client
	// 'C' = Encryption key client to server
	// 'D' = Encryption key server to client
	// 'E' = Integrity key client to server
	// 'F' = Integrity key server to client

	// 1. Derive Keys
	// AES-128 requires 16-byte keys and IVs.
	// HMAC-SHA2-256 requires 32-byte keys.
	clientIV := deriveKey(kBytes, hBytes, sessionId, 'A', 16)
	serverIV := deriveKey(kBytes, hBytes, sessionId, 'B', 16)

	clientKey := deriveKey(kBytes, hBytes, sessionId, 'C', 16)
	serverKey := deriveKey(kBytes, hBytes, sessionId, 'D', 16)

	clientMacKey := deriveKey(kBytes, hBytes, sessionId, 'E', 32)
	serverMacKey := deriveKey(kBytes, hBytes, sessionId, 'F', 32)

	// 2. Setup AES-CTR Encrypter (Client -> Server)
	blockClient, err := aes.NewCipher(clientKey)
	if err != nil {
		return nil, err
	}
	encrypter := cipher.NewCTR(blockClient, clientIV)

	// 3. Setup AES-CTR Decrypter (Server -> Client)
	blockServer, err := aes.NewCipher(serverKey)
	if err != nil {
		return nil, err
	}
	decrypter := cipher.NewCTR(blockServer, serverIV)

	// 4. Setup HMAC Hashers
	macWriter := hmac.New(sha256.New, clientMacKey)
	macReader := hmac.New(sha256.New, serverMacKey)

	return &SSHState{
		encrypter: encrypter,
		decrypter: decrypter,
		macWriter: macWriter,
		macReader: macReader,
		writeSeq:  0, // Reset
		readSeq:   0, // Reset
		sessionId: sessionId,
	}, nil
}

func deriveKey(k, h, sessionId []byte, tag byte, length int) []byte {
	hash := sha256.New()

	// K (Shared Secret) MUST be encoded as mpint (length + data)
	writeBytesHash(hash, k)

	// H (Exchange Hash) MUST be raw bytes (NO length prefix)
	hash.Write(h)

	// Tag (Single char)
	hash.Write([]byte{tag})

	// SessionID MUST be raw bytes (NO length prefix)
	hash.Write(sessionId)

	key := hash.Sum(nil)
	for len(key) < length {
		hash.Reset()
		writeBytesHash(hash, k)
		hash.Write(h) // Fix here too
		hash.Write(key)
		key = append(key, hash.Sum(nil)...)
	}
	return key[:length]
}
