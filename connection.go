package main

import (
	"bytes"
	f "fmt"
	"net"
	n "net"
)

func setupConnection(hostname string, port int, user string) (n.Conn, []byte, error) {
	f.Println("Initiating SSH connection...")

	address := n.JoinHostPort(hostname, f.Sprintf("%d", port))
	conn, err := n.Dial("tcp", address)
	if err != nil {
		return nil, nil, err
	}
	f.Printf("Connected to %s:%d\n", hostname, port)

	// 1. Send Client Version
	// RFC requires \r\n at the end
	clientVersion := "SSH-2.0-GoSHELL_0.1"
	_, err = conn.Write([]byte(clientVersion + "\r\n"))
	if err != nil {
		return nil, nil, err
	}

	// 2. Read Server Version (BYTE-BY-BYTE)
	// We cannot use conn.Read(buffer) because it will over-read into the KEXINIT packet.
	var versionBuf []byte
	tmp := make([]byte, 1)
	for {
		_, err := conn.Read(tmp)
		if err != nil {
			return nil, nil, err
		}

		// Stop exactly at the newline
		if tmp[0] == '\n' {
			break
		}
		versionBuf = append(versionBuf, tmp[0])
	}

	// 3. Clean up the version string
	// This removes the trailing \r if present, but keeps the crucial version text
	serverVersionClean := bytes.TrimSpace(versionBuf)
	f.Printf("Server Version: %s\n", serverVersionClean)

	return conn, serverVersionClean, nil
}

func sendClientECDHPublicKey(conn net.Conn, publicKey []byte) error {
	payload := new(bytes.Buffer)
	payload.WriteByte(30) // SSH_MSG_KEX_ECDH_INIT
	writeBytes(payload, publicKey)

	return writePacket(conn, payload.Bytes())
}
