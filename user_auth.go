package main

// Version 0.2 - Beta
// user_auth.go - User Authentication Handling
// Author: CyberPanther232

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	bin "encoding/binary"
	"encoding/pem"
	f "fmt"
	"math/big"
	"net"
	"os"
	"runtime"
	"strings"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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
		// Fallback to SSH agent (handles FIDO keys and other formats)
		f.Printf("Private key load failed (%v). Trying SSH agent...\n", err)
		return performKeybasedAuthUsingAgent(conn, state, username)
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

	// Build signature data to match OpenSSH exactly
	toSign := buildUserAuthSignatureData(state.sessionId, username, algo, pubBlob)
	f.Printf("toSign (agent-specific, len=%d): %s\n", len(toSign.Bytes()), base64.StdEncoding.EncodeToString(toSign.Bytes()))
	f.Printf("toSign (agent, len=%d): %s\n", len(toSign.Bytes()), base64.StdEncoding.EncodeToString(toSign.Bytes()))
	f.Printf("toSign (direct, len=%d): %s\n", len(toSign.Bytes()), base64.StdEncoding.EncodeToString(toSign.Bytes()))

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
	case *ecdsa.PrivateKey:
		var inner []byte
		algo := ecdsaAlgoName(k)
		switch algo {
		case "ecdsa-sha2-nistp256":
			h := sha256.Sum256(toSign.Bytes())
			r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
			if err != nil {
				return err
			}
			inner = marshalECDSASignature(r, s)
		case "ecdsa-sha2-nistp384":
			h := sha512.Sum384(toSign.Bytes())
			r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
			if err != nil {
				return err
			}
			inner = marshalECDSASignature(r, s)
		case "ecdsa-sha2-nistp521":
			h := sha512.Sum512(toSign.Bytes())
			r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
			if err != nil {
				return err
			}
			inner = marshalECDSASignature(r, s)
		default:
			return f.Errorf("unsupported ECDSA curve for SSH: %s", algo)
		}
		sig = inner
		sigAlgo = algo
	default:
		return f.Errorf("unsupported private key type for signing")
	}

	// Signature field: Standard SSH signature
	sigField := new(bytes.Buffer)
	writeString(sigField, sigAlgo)
	writeBytes(sigField, sig)

	f.Printf("sigField (direct, len=%d): %s\n", len(sigField.Bytes()), base64.StdEncoding.EncodeToString(sigField.Bytes()))
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

// performKeybasedAuthWithPassphrase mirrors performKeybasedAuth but decrypts the key with a passphrase.
func performKeybasedAuthWithPassphrase(conn net.Conn, state *SSHState, username string, identityPath string, passphrase string) error {
	key, algo, pubBlob, err := loadPrivateKeyWithPassphrase(identityPath, passphrase)
	if err != nil {
		return err
	}

	// Probe
	probe := new(bytes.Buffer)
	probe.WriteByte(50)
	writeString(probe, username)
	writeString(probe, "ssh-connection")
	writeString(probe, "publickey")
	probe.WriteByte(0)
	writeString(probe, algo)
	writeBytes(probe, pubBlob)
	if err := writeEncryptedPacket(conn, state, probe.Bytes()); err != nil {
		return err
	}
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

	// Signed request
	signed := new(bytes.Buffer)
	signed.WriteByte(50)
	writeString(signed, username)
	writeString(signed, "ssh-connection")
	writeString(signed, "publickey")
	signed.WriteByte(1)
	writeString(signed, algo)
	writeBytes(signed, pubBlob)

	toSign := buildUserAuthSignatureData(state.sessionId, username, algo, pubBlob)
	f.Printf("toSign (passphrase, len=%d): %s\n", len(toSign.Bytes()), base64.StdEncoding.EncodeToString(toSign.Bytes()))

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
	case *ecdsa.PrivateKey:
		algo := ecdsaAlgoName(k)
		switch algo {
		case "ecdsa-sha2-nistp256":
			h := sha256.Sum256(toSign.Bytes())
			r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
			if err != nil {
				return err
			}
			sig = marshalECDSASignature(r, s)
			sigAlgo = algo
		case "ecdsa-sha2-nistp384":
			h := sha512.Sum384(toSign.Bytes())
			r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
			if err != nil {
				return err
			}
			sig = marshalECDSASignature(r, s)
			sigAlgo = algo
		case "ecdsa-sha2-nistp521":
			h := sha512.Sum512(toSign.Bytes())
			r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
			if err != nil {
				return err
			}
			sig = marshalECDSASignature(r, s)
			sigAlgo = algo
		default:
			return f.Errorf("unsupported ECDSA curve for SSH: %s", algo)
		}
	default:
		return f.Errorf("unsupported private key type for signing")
	}

	sigField := new(bytes.Buffer)
	writeString(sigField, sigAlgo)
	writeBytes(sigField, sig)
	f.Printf("sigField (passphrase, len=%d): %s\n", len(sigField.Bytes()), base64.StdEncoding.EncodeToString(sigField.Bytes()))
	writeBytes(signed, sigField.Bytes())

	if err := writeEncryptedPacket(conn, state, signed.Bytes()); err != nil {
		return err
	}
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
			pub, _ := ssh.NewPublicKey(k.Public())
			return k, ecdsaAlgoName(k), pub.Marshal(), nil
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
			pub, _ := ssh.NewPublicKey(key.Public())
			return key, ecdsaAlgoName(key), pub.Marshal(), nil
		}
	}

	// Try PKCS#1 with DER
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		pub, _ := ssh.NewPublicKey(k.Public())
		return k, "ssh-rsa", pub.Marshal(), nil
	}

	return nil, "", nil, f.Errorf("unsupported or unreadable private key at %s (supported: ssh-rsa, ssh-ed25519, ecdsa)", path)
}

func loadPrivateKeyWithPassphrase(path string, passphrase string) (interface{}, string, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", nil, err
	}
	raw, err := ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(passphrase))
	if err != nil {
		return nil, "", nil, err
	}
	switch k := raw.(type) {
	case *rsa.PrivateKey:
		pub, _ := ssh.NewPublicKey(k.Public())
		return k, "ssh-rsa", pub.Marshal(), nil
	case ed25519.PrivateKey:
		pub, _ := ssh.NewPublicKey(k.Public())
		return k, "ssh-ed25519", pub.Marshal(), nil
	case *ecdsa.PrivateKey:
		pub, _ := ssh.NewPublicKey(k.Public())
		return k, ecdsaAlgoName(k), pub.Marshal(), nil
	default:
		return nil, "", nil, f.Errorf("unsupported private key type")
	}
}

// performKeybasedAuthUsingAgent tries all identities from SSH agent
func performKeybasedAuthUsingAgent(conn net.Conn, state *SSHState, username string) error {
	aconn, err := connectSSHAgent()
	if err != nil {
		return err
	}
	defer aconn.Close()

	ac := agent.NewClient(aconn)
	keys, err := ac.List()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return f.Errorf("ssh-agent has no loaded keys")
	}
	f.Printf("ssh-agent listed %d key(s):\n", len(keys))
	for i, k := range keys {
		f.Printf("  [%d] format=%s comment=%s\n", i, k.Format, k.Comment)
	}

	for _, k := range keys {
		algo := k.Format
		pubBlob := k.Blob

		// 1. Probe
		probe := new(bytes.Buffer)
		probe.WriteByte(50)
		writeString(probe, username)
		writeString(probe, "ssh-connection")
		writeString(probe, "publickey")
		probe.WriteByte(0)
		writeString(probe, algo)
		writeBytes(probe, pubBlob)
		if err := writeEncryptedPacket(conn, state, probe.Bytes()); err != nil {
			return err
		}
		resp, err := readEncryptedPacket(conn, state)
		if err != nil {
			return err
		}
		if len(resp) == 0 {
			continue
		}
		if resp[0] == 51 {
			methods, partial := parseUserAuthFailure(resp)
			f.Printf("Agent key rejected. Methods that can continue: %v (partial=%v)\n", methods, partial)
			continue
		}
		if resp[0] != 60 {
			continue // try next key
		}

		// 2. Signed request using agent
		signed := new(bytes.Buffer)
		signed.WriteByte(50)
		writeString(signed, username)
		writeString(signed, "ssh-connection")
		writeString(signed, "publickey")
		signed.WriteByte(1)
		writeString(signed, algo)
		writeBytes(signed, pubBlob)

		toSign := buildUserAuthSignatureData(state.sessionId, username, algo, pubBlob)

		pub, err := ssh.ParsePublicKey(pubBlob)
		if err != nil {
			return err
		}
		sig, err := ac.Sign(pub, toSign.Bytes())
		if err != nil {
			// try next key
			continue
		}

		// Standard SSH signature
		sigField := new(bytes.Buffer)
		writeString(sigField, sig.Format)
		writeBytes(sigField, sig.Blob)

		f.Printf("sigField (agent, len=%d): %s\n", len(sigField.Bytes()), base64.StdEncoding.EncodeToString(sigField.Bytes()))
		writeBytes(signed, sigField.Bytes())

		if err := writeEncryptedPacket(conn, state, signed.Bytes()); err != nil {
			return err
		}
		final, err := readEncryptedPacket(conn, state)
		if err != nil {
			return err
		}
		if len(final) > 0 {
			switch final[0] {
			case 52:
				f.Println("Key-based authentication successful via ssh-agent.")
				return nil
			case 51:
				methods, partial := parseUserAuthFailure(final)
				f.Printf("Agent-signed auth failed. Methods that can continue: %v (partial=%v)\n", methods, partial)
			}
		}
	}

	return f.Errorf("ssh-agent keys were not accepted by server")
}

// performKeybasedAuthUsingAgentWithPub filters the agent keys to a specific public key blob
func performKeybasedAuthUsingAgentWithPub(conn net.Conn, state *SSHState, username string, expectedPubBlob []byte) error {
	aconn, err := connectSSHAgent()
	if err != nil {
		return err
	}
	defer aconn.Close()

	ac := agent.NewClient(aconn)
	keys, err := ac.List()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return f.Errorf("ssh-agent has no loaded keys")
	}
	for _, k := range keys {
		if bytes.Equal(k.Blob, expectedPubBlob) {
			// Try only this key
			algo := k.Format
			pubBlob := k.Blob

			probe := new(bytes.Buffer)
			probe.WriteByte(50)
			writeString(probe, username)
			writeString(probe, "ssh-connection")
			writeString(probe, "publickey")
			probe.WriteByte(0)
			writeString(probe, algo)
			writeBytes(probe, pubBlob)
			if err := writeEncryptedPacket(conn, state, probe.Bytes()); err != nil {
				return err
			}
			resp, err := readEncryptedPacket(conn, state)
			if err != nil {
				return err
			}
			if len(resp) == 0 {
				return f.Errorf("empty server response to probe")
			}
			if resp[0] == 51 {
				methods, partial := parseUserAuthFailure(resp)
				return f.Errorf("agent key rejected. Methods that can continue: %v (partial=%v)", methods, partial)
			}
			if resp[0] != 60 {
				return f.Errorf("server did not accept agent key (code=%d)", resp[0])
			}

			signed := new(bytes.Buffer)
			signed.WriteByte(50)
			writeString(signed, username)
			writeString(signed, "ssh-connection")
			writeString(signed, "publickey")
			signed.WriteByte(1)
			writeString(signed, algo)
			writeBytes(signed, pubBlob)

			toSign := buildUserAuthSignatureData(state.sessionId, username, algo, pubBlob)

			pub, err := ssh.ParsePublicKey(pubBlob)
			if err != nil {
				return err
			}
			sig, err := ac.Sign(pub, toSign.Bytes())
			if err != nil {
				return err
			}

			sigField := new(bytes.Buffer)
			writeString(sigField, sig.Format)
			writeBytes(sigField, sig.Blob)

			f.Printf("sigField (agent-specific, len=%d): %s\n", len(sigField.Bytes()), base64.StdEncoding.EncodeToString(sigField.Bytes()))
			writeBytes(signed, sigField.Bytes())

			if err := writeEncryptedPacket(conn, state, signed.Bytes()); err != nil {
				return err
			}
			final, err := readEncryptedPacket(conn, state)
			if err != nil {
				return err
			}
			if len(final) > 0 {
				switch final[0] {
				case 52:
					f.Println("Key-based authentication successful via ssh-agent (specific key).")
					return nil
				case 51:
					methods, partial := parseUserAuthFailure(final)
					return f.Errorf("agent-signed authentication failed. Methods: %v (partial=%v)", methods, partial)
				}
			}
			return f.Errorf("server rejected agent-signed authentication (code=%d)", final[0])
		}
	}
	return f.Errorf("expected key not found in ssh-agent")
}

// readAuthorizedPubBlob loads a .pub authorized key file and returns the SSH public key blob
func readAuthorizedPubBlob(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, err
	}
	return pub.Marshal(), nil
}

// performKeybasedAuthUsingAgentPreferIdentity attempts agent auth prioritizing the identity's .pub fingerprint
func performKeybasedAuthUsingAgentPreferIdentity(conn net.Conn, state *SSHState, username string, identityPath string) error {
	// If a .pub file exists, use exact blob match first
	if _, err := os.Stat(identityPath + ".pub"); err == nil {
		if blob, err := readAuthorizedPubBlob(identityPath + ".pub"); err == nil {
			if err := performKeybasedAuthUsingAgentWithPub(conn, state, username, blob); err == nil {
				return nil
			}
		}
	}

	// Otherwise, enumerate agent keys and prefer same fingerprint as identity (if readable)
	aconn, err := connectSSHAgent()
	if err != nil {
		return err
	}
	defer aconn.Close()
	ac := agent.NewClient(aconn)
	keys, err := ac.List()
	if err != nil {
		return err
	}
	fprint := ""
	if _, err := os.Stat(identityPath + ".pub"); err == nil {
		if data, err := os.ReadFile(identityPath + ".pub"); err == nil {
			if pub, _, _, _, err := ssh.ParseAuthorizedKey(data); err == nil {
				fprint = ssh.FingerprintSHA256(pub)
			}
		}
	}
	// Try matching fingerprint first
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			continue
		}
		if fprint != "" && ssh.FingerprintSHA256(pub) == fprint {
			// Found matching key – authenticate using specific key path
			return performKeybasedAuthUsingAgentWithPub(conn, state, username, k.Blob)
		}
	}
	// Fall back to any agent key
	return performKeybasedAuthUsingAgent(conn, state, username)
}

// parseUserAuthFailure extracts the name-list of methods that can continue and partial success flag from SSH_MSG_USERAUTH_FAILURE
func parseUserAuthFailure(payload []byte) ([]string, bool) {
	// payload: [51][string methods][boolean partial]
	r := bytes.NewReader(payload[1:])
	// read methods
	lenBuf := make([]byte, 4)
	if _, err := r.Read(lenBuf); err != nil {
		return nil, false
	}
	n := bin.BigEndian.Uint32(lenBuf)
	m := make([]byte, n)
	if _, err := r.Read(m); err != nil {
		return nil, false
	}
	// read partial
	b := make([]byte, 1)
	if _, err := r.Read(b); err != nil {
		return strings.Split(string(m), ","), false
	}
	return strings.Split(string(m), ","), b[0] != 0
}

func connectSSHAgent() (net.Conn, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" && runtime.GOOS == "windows" {
		sock = `\\.\pipe\openssh-ssh-agent`
	}
	if sock == "" {
		return nil, f.Errorf("SSH_AUTH_SOCK not set")
	}
	if runtime.GOOS == "windows" && strings.HasPrefix(strings.ToLower(sock), `\\.\pipe\`) {
		return winio.DialPipe(sock, nil)
	}
	return net.Dial("unix", sock)
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
		case *rsa.PrivateKey, ed25519.PrivateKey, *ecdsa.PrivateKey:
			return nil
		default:
			return f.Errorf("unsupported identity key type (supported: ssh-rsa, ssh-ed25519, ecdsa)")
		}
	}
	return err
}

// marshalECDSASignature encodes ECDSA r,s as SSH signature blob (two mpints).
func marshalECDSASignature(r, s *big.Int) []byte {
	buf := new(bytes.Buffer)
	writeMPInt(buf, r)
	writeMPInt(buf, s)
	return buf.Bytes()
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

// buildUserAuthSignatureData constructs the exact byte sequence OpenSSH signs for
// publickey user authentication:
// string sessionId, byte 50, string username, string "ssh-connection",
// string "publickey", boolean TRUE, string algorithm, string publickey blob.
func buildUserAuthSignatureData(sessionId []byte, username string, algo string, pubBlob []byte) *bytes.Buffer {
	buf := new(bytes.Buffer)
	// Session identifier MUST be encoded as SSH string
	writeBytes(buf, sessionId)
	// The following reproduce SSH_MSG_USERAUTH_REQUEST fields (starting at msg number)
	buf.WriteByte(50)
	writeString(buf, username)
	writeString(buf, "ssh-connection")
	writeString(buf, "publickey")
	buf.WriteByte(1) // TRUE
	writeString(buf, algo)
	writeBytes(buf, pubBlob)
	return buf
}
