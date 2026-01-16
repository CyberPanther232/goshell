package main

// Version 0.2 - Beta
// read.go - Packet Reading and Decryption
// Author: CyberPanther232

import (
	"crypto/hmac"
	"encoding/binary"
	bin "encoding/binary"
	f "fmt"
	"io"
	"net"
)

func readEncryptedPacket(conn net.Conn, state *SSHState) ([]byte, error) {
	// 1. Read encrypted header (4 bytes)
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	// Decrypt header to get packet length
	decryptedHeader := make([]byte, 4)
	state.decrypter.XORKeyStream(decryptedHeader, header)
	packetLen := binary.BigEndian.Uint32(decryptedHeader)

	// 2. Read encrypted body of packet_len bytes
	encryptedBody := make([]byte, packetLen)
	if _, err := io.ReadFull(conn, encryptedBody); err != nil {
		return nil, err
	}

	// Decrypt body
	body := make([]byte, packetLen)
	state.decrypter.XORKeyStream(body, encryptedBody)

	// 3. Read MAC
	serverMac := make([]byte, state.macReader.Size())
	if _, err := io.ReadFull(conn, serverMac); err != nil {
		return nil, err
	}

	// 4. Verify MAC over plaintext [len][body]
	plaintextFull := append(decryptedHeader, body...)
	state.macReader.Reset()
	bin.Write(state.macReader, bin.BigEndian, state.readSeq)
	state.macReader.Write(plaintextFull)
	expectedMac := state.macReader.Sum(nil)

	if !hmac.Equal(serverMac, expectedMac) {
		return nil, f.Errorf("MAC mismatch on packet %d", state.readSeq)
	}

	// 5. Extract payload from body
	paddingLen := body[0]
	if int(paddingLen) >= len(body) {
		return nil, f.Errorf("invalid padding length")
	}
	payload := body[1 : len(body)-int(paddingLen)]

	// 6. Increment read sequence
	state.readSeq++
	return payload, nil
}

func readString(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	length := bin.BigEndian.Uint32(lenBuf)

	strBuf := make([]byte, length)
	if _, err := io.ReadFull(r, strBuf); err != nil {
		return nil, err
	}
	return strBuf, nil
}

func readPacket(conn net.Conn) ([]byte, error) {
	// 1. Read the first 4 bytes to get Packet Length
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	packetLen := binary.BigEndian.Uint32(lenBuf)

	// 2. Read the rest of the packet (Padding Len + Payload + Padding)
	rest := make([]byte, packetLen)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return nil, err
	}

	// 3. Parse Padding Length (first byte of 'rest')
	paddingLen := rest[0]

	// 4. Extract Payload
	// Payload starts at rest[1]
	// Payload ends at len(rest) - paddingLen
	if len(rest) < int(paddingLen)+1 {
		return nil, f.Errorf("invalid packet length")
	}
	payload := rest[1 : len(rest)-int(paddingLen)]

	return payload, nil
}
