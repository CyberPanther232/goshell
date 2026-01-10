package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	bin "encoding/binary"
	"encoding/pem"
	f "fmt"
	"math/big"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func performPasswordAuth(conn net.Conn, state *SSHState, username string, password string) error {
	// 1. Construct Payload
	payload := new(bytes.Buffer)
	payload.WriteByte(50) // SSH_MSG_USERAUTH_REQUEST
	writeString(payload, username)
	writeString(payload, "ssh-connection")
	writeString(payload, "password")
	payload.WriteByte(0) // FALSE: Not changing password
	writeString(payload, password)

	// 2. Send Packet
	if err := writeEncryptedPacket(conn, state, payload.Bytes()); err != nil {
		return err
	}

	// 3. Response loop
	for {
		response, err := readEncryptedPacket(conn, state)
		if err != nil {
			return err
		}

		switch response[0] {
		case 52: // SSH_MSG_USERAUTH_SUCCESS
			f.Println("Password authentication successful.")
			return nil
		case 51: // SSH_MSG_USERAUTH_FAILURE
			return f.Errorf("Password authentication failed.")
		case 53: // SSH_MSG_USERAUTH_BANNER
			return f.Errorf("Received SSH_MSG_USERAUTH_BANNER from server: %s", string(response[1:]))
		default:
			f.Printf("Received unexpected message type %d during authentication\n", response[0])
			return f.Errorf("Unexpected message type %d", response[0])
		}
	}
}

// performKeybasedAuth attempts publickey authentication using an RSA private key at identityPath.
// Flow:
// 1) Probe with signature = FALSE to receive SSH_MSG_USERAUTH_PK_OK (60)
// 2) Send signed request (signature = TRUE). Expect SSH_MSG_USERAUTH_SUCCESS (52)
func performKeybasedAuth(conn net.Conn, state *SSHState, username string, identityPath string) error {
	key, algo, pubBlob, err := loadPrivateKey(identityPath)
	if err != nil {
		return err
	}

	// 1. Probe request (signature = FALSE)
	probe := new(bytes.Buffer)
	probe.WriteByte(50) // SSH_MSG_USERAUTH_REQUEST
	writeString(probe, username)
	writeString(probe, "ssh-connection")
	writeString(probe, "publickey")
	probe.WriteByte(0)         // FALSE (no signature)
	writeString(probe, algo)   // e.g., "ssh-rsa"
	writeBytes(probe, pubBlob) // full public key blob (includes algo+e+n)

	if err := writeEncryptedPacket(conn, state, probe.Bytes()); err != nil {
		return err
	}

	// Expect SSH_MSG_USERAUTH_PK_OK (60)
	resp, err := readEncryptedPacket(conn, state)
	if err != nil {
		return err
	}
	if len(resp) == 0 || resp[0] != 60 {
		if len(resp) > 0 && resp[0] == 51 {
			return f.Errorf("Key-based authentication not accepted (failure)")
		}
		return f.Errorf("Expected SSH_MSG_USERAUTH_PK_OK (60), got %d", resp[0])
	}

	// 2. Signed request (signature = TRUE)
	signed := new(bytes.Buffer)
	signed.WriteByte(50) // SSH_MSG_USERAUTH_REQUEST
	writeString(signed, username)
	writeString(signed, "ssh-connection")
	writeString(signed, "publickey")
	signed.WriteByte(1) // TRUE (with signature)
	writeString(signed, algo)
	writeBytes(signed, pubBlob)

	// Build signature data: sessionId (raw) + the above packet contents (starting at msg number)
	toSign := new(bytes.Buffer)
	toSign.Write(state.sessionId) // RAW (no length prefix)
	// Recreate the part after sessionId exactly
	sigInner := new(bytes.Buffer)
	sigInner.WriteByte(50)
	writeString(sigInner, username)
	writeString(sigInner, "ssh-connection")
	writeString(sigInner, "publickey")
	sigInner.WriteByte(1)
	writeString(sigInner, algo)
	writeBytes(sigInner, pubBlob)
	toSign.Write(sigInner.Bytes())

	// Compute RSA PKCS#1 v1.5 + SHA256 signature
	var sig []byte
	var sigAlgo string
	switch k := key.(type) {
	case *rsa.PrivateKey:
		h := sha256.Sum256(toSign.Bytes())
		s, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
		if err != nil {
			return err
		}
		sig = s
		sigAlgo = "rsa-sha2-256"
	case ed25519.PrivateKey:
		s := ed25519.Sign(k, toSign.Bytes())
		sig = s
		sigAlgo = "ssh-ed25519"
	default:
		return f.Errorf("unsupported private key type for signing")
	}

	// Signature field: string algorithm name + string signature
	sigField := new(bytes.Buffer)
	writeString(sigField, sigAlgo)
	writeBytes(sigField, sig)
	writeBytes(signed, sigField.Bytes())

	if err := writeEncryptedPacket(conn, state, signed.Bytes()); err != nil {
		return err
	}

	// Final response
	final, err := readEncryptedPacket(conn, state)
	if err != nil {
		return err
	}
	switch final[0] {
	case 52:
		f.Println("Key-based authentication successful.")
		return nil
	case 51:
		return f.Errorf("Key-based authentication failed.")
	default:
		return f.Errorf("Unexpected message type %d during key auth", final[0])
	}
}

// loadRSAPrivateKey loads an RSA private key from a PEM file and returns:
// - rsa.PrivateKey
// - algorithm name ("ssh-rsa")
// - public key blob (RFC 4253): string algo + mpint e + mpint n
func loadPrivateKey(path string) (interface{}, string, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", nil, err
	}

	// Try OpenSSH format via x/crypto/ssh
	if raw, err := ssh.ParseRawPrivateKey(data); err == nil {
		switch k := raw.(type) {
		case *rsa.PrivateKey:
			pub, _ := ssh.NewPublicKey(k.Public())
			return k, "ssh-rsa", pub.Marshal(), nil
		case ed25519.PrivateKey:
			pub, _ := ssh.NewPublicKey(k.Public())
			return k, "ssh-ed25519", pub.Marshal(), nil
		case *ecdsa.PrivateKey:
			algo := ecdsaAlgoName(k)
			return nil, "", nil, f.Errorf("unsupported private key type: %s (supported: ssh-rsa, ssh-ed25519)", algo)
		default:
			return nil, "", nil, f.Errorf("unsupported private key type (supported: ssh-rsa, ssh-ed25519)")
		}
	}

	// Try PEM decoding then parse
	// Handle common PEM wrappers
	var der []byte
	if p, _ := pemDecode(data); p != nil {
		der = p
	} else {
		der = data
	}

	// Try PKCS#8
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := k.(type) {
		case *rsa.PrivateKey:
			pub, _ := ssh.NewPublicKey(key.Public())
			return key, "ssh-rsa", pub.Marshal(), nil
		case ed25519.PrivateKey:
			pub, _ := ssh.NewPublicKey(key.Public())
			return key, "ssh-ed25519", pub.Marshal(), nil
		case *ecdsa.PrivateKey:
			algo := ecdsaAlgoName(key)
			return nil, "", nil, f.Errorf("unsupported private key type: %s (supported: ssh-rsa, ssh-ed25519)", algo)
		}
	}

	// Try PKCS#1 with DER
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		pub, _ := ssh.NewPublicKey(k.Public())
		return k, "ssh-rsa", pub.Marshal(), nil
	}

	return nil, "", nil, f.Errorf("unsupported or unreadable private key at %s (supported: ssh-rsa, ssh-ed25519)", path)
}

// ecdsaAlgoName maps ECDSA private keys to SSH algo names for messaging.
func ecdsaAlgoName(k *ecdsa.PrivateKey) string {
	if k == nil || k.PublicKey.Curve == nil {
		return "ecdsa"
	}
	name := k.PublicKey.Curve.Params().Name
	switch name {
	case "P-256":
		return "ecdsa-sha2-nistp256"
	case "P-384":
		return "ecdsa-sha2-nistp384"
	case "P-521":
		return "ecdsa-sha2-nistp521"
	default:
		return "ecdsa"
	}
}

// ensureSupportedIdentity validates the identity file and returns a clear error if unsupported.
func ensureSupportedIdentity(path string) error {
	key, _, _, err := loadPrivateKey(path)
	if err == nil {
		switch key.(type) {
		case *rsa.PrivateKey, ed25519.PrivateKey:
			return nil
		default:
			return f.Errorf("unsupported identity key type (supported: ssh-rsa, ssh-ed25519)")
		}
	}
	return err
}

// Minimal PEM decode: returns DER block of the first PEM section, or nil
func pemDecode(b []byte) ([]byte, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, f.Errorf("no PEM block found")
	}
	return block.Bytes, nil
}

func marshalRSAPublicKeyBlob(pub *rsa.PublicKey) []byte {
	buf := new(bytes.Buffer)
	writeString(buf, "ssh-rsa")
	writeMPInt(buf, bigFromInt(pub.E))
	writeMPInt(buf, pub.N)
	return buf.Bytes()
}

func writeMPInt(buf *bytes.Buffer, x *big.Int) {
	if x == nil {
		bin.Write(buf, bin.BigEndian, uint32(0))
		return
	}
	b := x.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0x00}, b...)
	}
	bin.Write(buf, bin.BigEndian, uint32(len(b)))
	buf.Write(b)
}

func bigFromInt(i int) *big.Int {
	var b big.Int
	b.SetInt64(int64(i))
	return &b
}
