package main

// Version 0.2 - Beta
// write.go - Packet Writing and Encryption
// Author: CyberPanther232

import (
	"bytes"
	"crypto/rand"
	bin "encoding/binary"
	"io"
	"net"
)

func writeEncryptedPacket(conn net.Conn, state *SSHState, payload []byte) error {
	blockSize := 16

	// 1. Padding calculation per RFC 4253 (encrypted phase)
	currentLen := 4 + 1 + len(payload)
	paddingLen := blockSize - (currentLen % blockSize)
	if paddingLen < 4 {
		paddingLen += blockSize
	}

	packetLen := uint32(len(payload) + paddingLen + 1)

	// Construct plaintext: [packet_length][padding_length][payload][padding]
	buf := new(bytes.Buffer)
	bin.Write(buf, bin.BigEndian, packetLen)
	buf.WriteByte(byte(paddingLen))
	buf.Write(payload)

	padding := make([]byte, paddingLen)
	io.ReadFull(rand.Reader, padding)
	buf.Write(padding)
	plaintext := buf.Bytes()

	// 2. MAC over sequence number and plaintext packet
	state.macWriter.Reset()
	bin.Write(state.macWriter, bin.BigEndian, state.writeSeq)
	state.macWriter.Write(plaintext)
	mac := state.macWriter.Sum(nil)

	// 3. Encrypt entire plaintext (including packet_length)
	ciphertext := make([]byte, len(plaintext))
	state.encrypter.XORKeyStream(ciphertext, plaintext)

	// 4. Send: encrypted packet + mac
	finalPacket := append(ciphertext, mac...)
	if _, err := conn.Write(finalPacket); err != nil {
		return err
	}

	// 5. Increment write sequence
	state.writeSeq++
	return nil
}

func writePacket(conn net.Conn, payload []byte) error {
	blockSize := 8 // Standard for initial unencrypted phase

	// Calculate padding
	// Length field (4) + PaddingLen field (1) + PayloadLen + PaddingLen
	// Total length must be multiple of blockSize
	currentLen := 4 + 1 + len(payload)
	paddingLen := blockSize - (currentLen % blockSize)
	if paddingLen < 4 {
		paddingLen += blockSize
	}

	packetLen := uint32(len(payload) + paddingLen + 1) // +1 is for the padding_len byte itself

	buf := new(bytes.Buffer)

	// 1. Packet Length
	bin.Write(buf, bin.BigEndian, packetLen)

	// 2. Padding Length
	buf.WriteByte(byte(paddingLen))

	// 3. Payload
	buf.Write(payload)

	// 4. Padding (Random bytes)
	padding := make([]byte, paddingLen)
	io.ReadFull(rand.Reader, padding) // Fill with random
	buf.Write(padding)

	// Send over TCP
	_, err := conn.Write(buf.Bytes())
	return err
}

func writeString(buf *bytes.Buffer, str string) {
	bin.Write(buf, bin.BigEndian, uint32(len(str)))
	buf.WriteString(str)
}

func writeBytes(buf *bytes.Buffer, data []byte) {
	bin.Write(buf, bin.BigEndian, uint32(len(data)))
	buf.Write(data)
}
