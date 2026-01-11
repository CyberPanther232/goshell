package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	bin "encoding/binary"
	f "fmt"
	"hash"
	"io"
	"net"
	"os"
	"sync"

	"golang.org/x/term"
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
	sessionId := hBytes

	clientIV := deriveKey(kBytes, hBytes, sessionId, 'A', 16)
	serverIV := deriveKey(kBytes, hBytes, sessionId, 'B', 16)

	clientKey := deriveKey(kBytes, hBytes, sessionId, 'C', 16)
	serverKey := deriveKey(kBytes, hBytes, sessionId, 'D', 16)

	clientMacKey := deriveKey(kBytes, hBytes, sessionId, 'E', 32)
	serverMacKey := deriveKey(kBytes, hBytes, sessionId, 'F', 32)

	blockClient, err := aes.NewCipher(clientKey)
	if err != nil {
		return nil, err
	}
	encrypter := cipher.NewCTR(blockClient, clientIV)

	blockServer, err := aes.NewCipher(serverKey)
	if err != nil {
		return nil, err
	}
	decrypter := cipher.NewCTR(blockServer, serverIV)

	macWriter := hmac.New(sha256.New, clientMacKey)
	macReader := hmac.New(sha256.New, serverMacKey)

	return &SSHState{
		encrypter: encrypter,
		decrypter: decrypter,
		macWriter: macWriter,
		macReader: macReader,
		writeSeq:  0,
		readSeq:   0,
		sessionId: sessionId,
	}, nil
}

func deriveKey(k, h, sessionId []byte, tag byte, length int) []byte {
	hash := sha256.New()
	writeBytesHash(hash, k)
	hash.Write(h)
	hash.Write([]byte{tag})
	hash.Write(sessionId)
	key := hash.Sum(nil)
	for len(key) < length {
		hash.Reset()
		writeBytesHash(hash, k)
		hash.Write(h)
		hash.Write(key)
		key = append(key, hash.Sum(nil)...)
	}
	return key[:length]
}

// --- Session Logic ---

func startSession(conn net.Conn, state *SSHState) error {
	// Set Stdin to Raw Mode
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		oldState, err := term.MakeRaw(fd)
		if err != nil {
			f.Printf("Warning: Failed to set raw mode: %v\n", err)
		} else {
			defer term.Restore(fd, oldState)
		}
	}

	// 1. Open Channel "session"
	localChannelID := uint32(0)
	if err := openSessionChannel(conn, state, localChannelID); err != nil {
		return err
	}

	// 2. Wait for Confirmation
	remoteChannelID, err := waitForChannelConfirmation(conn, state, localChannelID)
	if err != nil {
		return err
	}
	f.Printf("Session Channel Opened. Remote ID: %d\n", remoteChannelID)

	// 3. Request PTY
	// Defaults: xterm, 80x24 (Simple default, can be improved)
	if err := requestPty(conn, state, remoteChannelID); err != nil {
		f.Printf("Warning: PTY request failed: %v\n", err)
	}

	// 4. Request Shell
	if err := requestShell(conn, state, remoteChannelID); err != nil {
		return err
	}
	f.Println("Remote shell started!")

	// 5. Start IO Loop
	var wg sync.WaitGroup
	wg.Add(2)

	// Remote -> Local
	go func() {
		defer wg.Done()
		for {
			payload, err := readEncryptedPacket(conn, state)
			if err != nil {
				logDebug("Read error: %v", err)
				if err != io.EOF {
					// Connection error
				}
				os.Exit(0) // Exit on connection loss
				return
			}
			if len(payload) == 0 {
				continue
			}

			// logDebug("Received packet type: %d", payload[0])

			switch payload[0] {
			case 94: // SSH_MSG_CHANNEL_DATA
				// [1 byte type] [4 bytes recipient] [string data]
				if len(payload) < 9 {
					continue
				}
				// Parse string data
				dataLen := bin.BigEndian.Uint32(payload[5:9])
				if uint32(len(payload)-9) < dataLen {
					continue
				}
				data := payload[9 : 9+dataLen]
				os.Stdout.Write(data)
				// logDebug("Received data: %q", data)

			case 97: // SSH_MSG_CHANNEL_CLOSE
				logDebug("Server closed channel")
				f.Println("\n[Channel Closed by Server] - Thanks for using GoSHELL!")
				os.Exit(0)

			case 98: // SSH_MSG_CHANNEL_REQUEST (e.g. exit-status)
				logDebug("Received channel request")
				// Ignored for now
			}
		}
	}()

	// Local -> Remote
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				logDebug("Stdin read error: %v", err)
				return
			}
			if n > 0 {
				data := buf[:n]
				logDebug("Read stdin: %q", data)
				// SSH_MSG_CHANNEL_DATA
				packet := new(bytes.Buffer)
				packet.WriteByte(94)
				bin.Write(packet, bin.BigEndian, remoteChannelID)
				writeBytes(packet, data)

				if err := writeEncryptedPacket(conn, state, packet.Bytes()); err != nil {
					logDebug("Write packet error: %v", err)
					return
				}
			}
		}
	}()
	wg.Wait()
	return nil
}

func openSessionChannel(conn net.Conn, state *SSHState, localID uint32) error {
	payload := new(bytes.Buffer)
	payload.WriteByte(90) // SSH_MSG_CHANNEL_OPEN
	writeString(payload, "session")
	bin.Write(payload, bin.BigEndian, localID)
	bin.Write(payload, bin.BigEndian, uint32(2097152)) // Window Size
	bin.Write(payload, bin.BigEndian, uint32(32768))   // Max Packet Size
	return writeEncryptedPacket(conn, state, payload.Bytes())
}

func waitForChannelConfirmation(conn net.Conn, state *SSHState, expectedLocalID uint32) (uint32, error) {
	for {
		payload, err := readEncryptedPacket(conn, state)
		if err != nil {
			return 0, err
		}
		if len(payload) == 0 {
			continue
		}

		if payload[0] == 91 { // SSH_MSG_CHANNEL_OPEN_CONFIRMATION
			// [1] [4 recipient (localID)] [4 sender (remoteID)] ...
			if len(payload) < 9 {
				return 0, f.Errorf("malformed channel confirmation")
			}
			recipient := bin.BigEndian.Uint32(payload[1:5])
			if recipient != expectedLocalID {
				continue // Not for our channel
			}
			remoteID := bin.BigEndian.Uint32(payload[5:9])
			return remoteID, nil
		} else if payload[0] == 92 { // SSH_MSG_CHANNEL_OPEN_FAILURE
			return 0, f.Errorf("channel open failed")
		}
		// Ignore global requests or debug messages
	}
}

func requestPty(conn net.Conn, state *SSHState, remoteID uint32) error {
	payload := new(bytes.Buffer)
	payload.WriteByte(98) // SSH_MSG_CHANNEL_REQUEST
	bin.Write(payload, bin.BigEndian, remoteID)
	writeString(payload, "pty-req")
	payload.WriteByte(0) // Want Reply (False) - fire and forget

	// TERM env var (e.g., "xterm")
	writeString(payload, "xterm-256color")

	// Dimensions
	bin.Write(payload, bin.BigEndian, uint32(80)) // cols
	bin.Write(payload, bin.BigEndian, uint32(24)) // rows
	bin.Write(payload, bin.BigEndian, uint32(0))  // width px
	bin.Write(payload, bin.BigEndian, uint32(0))  // height px

	// Terminal Modes (Encoded string)
	// Just sending empty modes (0) for now
	writeString(payload, "\x00")

	return writeEncryptedPacket(conn, state, payload.Bytes())
}

func requestShell(conn net.Conn, state *SSHState, remoteID uint32) error {
	payload := new(bytes.Buffer)
	payload.WriteByte(98) // SSH_MSG_CHANNEL_REQUEST
	bin.Write(payload, bin.BigEndian, remoteID)
	writeString(payload, "shell")
	payload.WriteByte(1) // Want Reply (True)

	if err := writeEncryptedPacket(conn, state, payload.Bytes()); err != nil {
		return err
	}

	// Wait for success/failure
	for {
		resp, err := readEncryptedPacket(conn, state)
		if err != nil {
			return err
		}
		if len(resp) > 0 && resp[0] == 99 { // SSH_MSG_CHANNEL_SUCCESS
			if bin.BigEndian.Uint32(resp[1:5]) == remoteID {
				return nil
			}
		}
		if len(resp) > 0 && resp[0] == 100 { // SSH_MSG_CHANNEL_FAILURE
			if bin.BigEndian.Uint32(resp[1:5]) == remoteID {
				return f.Errorf("shell request failed")
			}
		}
	}
}

func runCommand(conn net.Conn, state *SSHState, command string) error {
	// 1. Open Channel "session"
	localChannelID := uint32(0)
	if err := openSessionChannel(conn, state, localChannelID); err != nil {
		return err
	}

	// 2. Wait for Confirmation
	remoteChannelID, err := waitForChannelConfirmation(conn, state, localChannelID)
	if err != nil {
		return err
	}

	// 3. Send "exec" request
	if err := requestExec(conn, state, remoteChannelID, command); err != nil {
		return err
	}

	// 4. Read Output Loop
	for {
		payload, err := readEncryptedPacket(conn, state)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if len(payload) == 0 {
			continue
		}

		switch payload[0] {
		case 94: // SSH_MSG_CHANNEL_DATA
			// [1 byte type] [4 bytes recipient] [string data]
			if len(payload) < 9 {
				continue
			}
			dataLen := bin.BigEndian.Uint32(payload[5:9])
			if uint32(len(payload)-9) < dataLen {
				continue
			}
			data := payload[9 : 9+dataLen]
			os.Stdout.Write(data)

		case 97: // SSH_MSG_CHANNEL_CLOSE
			return nil

		case 98: // SSH_MSG_CHANNEL_REQUEST (exit-status)
			// check for exit-status
		}
	}
	return nil
}

func requestExec(conn net.Conn, state *SSHState, remoteID uint32, command string) error {
	payload := new(bytes.Buffer)
	payload.WriteByte(98) // SSH_MSG_CHANNEL_REQUEST
	bin.Write(payload, bin.BigEndian, remoteID)
	writeString(payload, "exec")
	payload.WriteByte(1) // Want Reply (True)
	writeString(payload, command)

	if err := writeEncryptedPacket(conn, state, payload.Bytes()); err != nil {
		return err
	}

	// Wait for success/failure
	for {
		resp, err := readEncryptedPacket(conn, state)
		if err != nil {
			return err
		}
		if len(resp) > 0 && resp[0] == 99 { // SSH_MSG_CHANNEL_SUCCESS
			if bin.BigEndian.Uint32(resp[1:5]) == remoteID {
				return nil
			}
		}
		if len(resp) > 0 && resp[0] == 100 { // SSH_MSG_CHANNEL_FAILURE
			if bin.BigEndian.Uint32(resp[1:5]) == remoteID {
				return f.Errorf("exec request failed")
			}
		}
	}
}
