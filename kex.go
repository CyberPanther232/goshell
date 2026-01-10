package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	bin "encoding/binary"
	f "fmt"
	"io"
	"math/big"
	"net"
	n "net"
)

// Added vc and vs parameters
// Updated Signature: Returns ([]byte, []byte) -> (SharedSecret, ExchangeHash)
func parseKeyExchangeReply(payload []byte, clientPrivKey *ecdh.PrivateKey, clientKexInit, serverKexInit, clientPubKey, vc, vs []byte) ([]byte, []byte) {
	r := bytes.NewReader(payload[1:])

	hostKeyBytes, _ := readString(r)
	serverEphemeralBytes, _ := readString(r)
	signatureBytes, _ := readString(r)

	f.Printf("Server Host Key Algo: %s\n", string(hostKeyBytes))
	f.Printf("Signature Blob Length: %d\n", len(signatureBytes))

	serverPub, err := ecdh.P256().NewPublicKey(serverEphemeralBytes)
	if err != nil {
		panic("Invalid server public key: " + err.Error())
	}

	sharedSecret, err := clientPrivKey.ECDH(serverPub)
	if err != nil {
		panic("ECDH failed")
	}

	// Convert to MPINT format
	kInt := new(big.Int).SetBytes(sharedSecret)
	kBytes := kInt.Bytes()
	if len(kBytes) > 0 && kBytes[0]&0x80 != 0 {
		kBytes = append([]byte{0x00}, kBytes...)
	}

	f.Printf("Shared Secret Calculated! Length: %d\n", len(kBytes))

	// Calculate Hash
	hash := calculateExchangeHash(vc, vs, clientKexInit, serverKexInit, hostKeyBytes, clientPubKey, serverEphemeralBytes, kBytes)
	f.Printf("Exchange Hash (H) Calculated! Length: %d\n", len(hash))

	// RETURN the calculated values
	return kBytes, hash
}

// Helper to write length-prefixed strings into the hasher
func writeStringHash(w io.Writer, s []byte) {
	binary.Write(w, binary.BigEndian, uint32(len(s)))
	w.Write(s)
}

// Helper specifically for mpint (re-using the logic from Step 1 usually best)
func writeBytesHash(w io.Writer, b []byte) {
	binary.Write(w, binary.BigEndian, uint32(len(b)))
	w.Write(b)
}

func sendNewKeys(conn net.Conn) error {
	// Payload is just the message byte 21
	return writePacket(conn, []byte{21})
}

func calculateExchangeHash(vc, vs, ic, is, ks, qc, qs, k []byte) []byte {
	h := sha256.New()

	writeStringHash(h, vc)
	writeStringHash(h, vs)
	writeStringHash(h, ic) // Note: This is the full payload of KEXINIT
	writeStringHash(h, is)
	writeStringHash(h, ks)
	writeStringHash(h, qc)
	writeStringHash(h, qs)
	writeBytesHash(h, k) // mpint format K

	return h.Sum(nil)
}

func generateECDHKeyPair() (*ecdh.PrivateKey, []byte, error) {
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	publicKey := privateKey.PublicKey().Bytes()
	return privateKey, publicKey, nil
}

func prepareKeyExchange(conn n.Conn) ([]byte, error) {
	f.Println("Starting key exchange...")
	payload := new(bytes.Buffer)

	payload.WriteByte(msgKexInit)

	cookie := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, cookie)
	if err != nil {
		return nil, err
	}
	payload.Write(cookie)

	// --- STRICT ALGORITHMS ---
	// Only offer exactly what we implemented in activateEncryption
	KexAlgos := "ecdh-sha2-nistp256"
	HostKeyAlgos := "ssh-ed25519,rsa-sha2-512,ssh-rsa"

	// FORCE AES-128-CTR
	Ciphers := "aes128-ctr"

	// FORCE HMAC-SHA2-256
	MACs := "hmac-sha2-256"

	Compression := "none"
	empty := ""

	writeString(payload, KexAlgos)
	writeString(payload, HostKeyAlgos)
	writeString(payload, Ciphers) // client to server cipher
	writeString(payload, Ciphers) // server to client cipher
	writeString(payload, MACs)    // client to server mac
	writeString(payload, MACs)    // server to client mac
	writeString(payload, Compression)
	writeString(payload, Compression)
	writeString(payload, empty)
	writeString(payload, empty)

	payload.WriteByte(0)                         // First KEX Packet Follows
	bin.Write(payload, bin.BigEndian, uint32(0)) // Reserved

	return payload.Bytes(), nil
}
