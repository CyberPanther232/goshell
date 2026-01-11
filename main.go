package main

import (
	f "fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// Constants
const msgKexInit = 20

// SSH RFC 4253
/*

SSH_MSG_CHANNEL_DATA
   byte      SSH_MSG_CHANNEL_DATA
   uint32    recipient channel
   string    data

*/

// RFC 4253 SSH Transport Layer Protocol
/*
	Page 6. Binary Packet Protocol

	Each packet is in the following format:

	uint32	packet_length
	byte	padding_length
	byte[n1]	payload; n1 = packet_length - padding_length - 1
	byte[n2]	padding; n2 = padding_length

	packet_length
	   The length of the packet in bytes, not including 'packet_length'
	   itself.

	padding_length
	   The length of the random padding.

	payload
	   The useful contents of the packet.  If compression has been
	   negotiated, this field is compressed. Initially, compression MUST be
	   "none".

	random padding
	   Arbitrary bytes that are added to make the length of the packet a
	   multiple of the cipher block size or 8, whichever is larger.  The
	   padding MUST be at least four bytes long.

	mac
		Message Authentication Code.  If message authentication has been
		negotiated, this field contains the MAC bytes.  The length of this
		field is determined by the negotiated MAC algorithm.

*/
func main() {

	args := os.Args[1:]

	parsedArgs, err := parseArgs(args)
	if err != nil {
		panic(err)
	}

	if parsedArgs["configurationPath"] == "" {
		parsedArgs["configurationPath"] = "goshell.conf"
	}

	configuration, err := loadConfig(parsedArgs["configurationPath"])
	if err != nil {
		panic(err)
	}

	if len(configuration) == 0 {
		f.Println("No configuration found. Please create a goshell.conf file.")
		return
	}

	var selected HostConfig
	var ok bool

	if parsedArgs["host"] == "" {
		f.Println("Available Hosts:")
		for host := range configuration {
			f.Println(" -", host)
		}
		choice := strings.TrimSpace(getUserInput("Select a host: "))
		selected, ok = configuration[choice]
	} else {
		selected, ok = configuration[strings.TrimSpace(parsedArgs["host"])]
	}

	if !ok {
		f.Println("Host not found in configuration.")
		return
	}

	// 1. Connection & Version Exchange
	conn, serverVersion, err := setupConnection(selected.Hostname, selected.Port, selected.User)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	clientVersion := []byte("SSH-2.0-GoSHELL_0.1")

	// 2. Client KEXINIT
	clientKexPayload, _ := prepareKeyExchange(conn)
	writePacket(conn, clientKexPayload)
	f.Println("Sent Client KEXINIT")

	// 3. Server KEXINIT
	serverKexPayload, err := readPacket(conn)
	if err != nil {
		f.Println("Failed to read Server KEXINIT. Did setupConnection over-read?")
		panic(err)
	}
	if len(serverKexPayload) > 0 && serverKexPayload[0] != 20 {
		panic(f.Sprintf("Expected Msg 20, got %d", serverKexPayload[0]))
	}
	f.Println("Received Server KEXINIT")

	// 4. Generate & Send ECDH Init
	privKey, pubKey, err := generateECDHKeyPair()
	if err != nil {
		panic(err)
	}
	err = sendClientECDHPublicKey(conn, pubKey)
	if err != nil {
		panic(err)
	}
	f.Println("Sent ECDH Init")

	// 5. Read ECDH Reply
	replyPayload, err := readPacket(conn)
	if err != nil {
		panic(err)
	}
	if replyPayload[0] != 31 {
		f.Printf("Unexpected packet: %d\n", replyPayload[0])
		return
	}
	f.Println("Received ECDH Reply.")

	// 6. Calculate Secrets (K and H)
	// We capture the returned values here!
	derivedKBytes, exchangeHash := parseKeyExchangeReply(replyPayload, privKey, clientKexPayload, serverKexPayload, pubKey, clientVersion, serverVersion)

	// 7. Send NEWKEYS (Msg 21)
	sendNewKeys(conn)
	f.Println("Sent NEWKEYS.")

	// 8. Receive NEWKEYS (Msg 21)
	serverNewKeys, err := readPacket(conn)
	if err != nil {
		panic(err)
	}
	if serverNewKeys[0] != 21 {
		panic("Expected SSH_MSG_NEWKEYS from server")
	}
	f.Println("Received NEWKEYS from server.")

	// 9. Activate Encryption
	sshState, err := activateEncryption(derivedKBytes, exchangeHash)
	if err != nil {
		panic(err)
	}

	// CRITICAL FIX: Synchronize BOTH counters independently
	// You have exchanged exactly 3 packets (KEXINIT, ECDH, NEWKEYS)
	sshState.writeSeq = 3
	sshState.readSeq = 3

	f.Println("------------------------------------------------")
	f.Println("ENCRYPTION ACTIVATED (AES-128-CTR + HMAC-SHA256)")
	f.Println("------------------------------------------------")

	// 10. Verify Encryption: Send Service Request
	// We ask for the "ssh-userauth" service. If the server replies, encryption works.

	// Packet: [SSH_MSG_SERVICE_REQUEST (5)] [String Length (12)] ["ssh-userauth"]
	serviceRequest := []byte{
		5,
		0, 0, 0, 12,
		's', 's', 'h', '-', 'u', 's', 'e', 'r', 'a', 'u', 't', 'h',
	}

	// Use writeEncryptedPacket (ensure you added this function!)
	f.Println("Sending Service Request (Encrypted)...")
	err = writeEncryptedPacket(conn, sshState, serviceRequest)
	if err != nil {
		panic(err)
	}

	// Read Encrypted Response
	// Use readEncryptedPacket (ensure you added this function!)
	response, err := readEncryptedPacket(conn, sshState)
	if err != nil {
		panic(err)
	}

	f.Printf("Decrypted Response Type: %d\n", response[0])

	if response[0] == 6 { // SSH_MSG_SERVICE_ACCEPT
		f.Println("SUCCESS: Server accepted our encrypted packet!")

		f.Println("SSH Connection Established and Encrypted!")
		if configuration[selected.Host].KeybasedAuthentication && selected.IdentityFile != "" {
			f.Println("Key-based authentication is enabled. Proceeding with authentication...")
			// Prefer agent using the identity’s fingerprint if available
			if err := performKeybasedAuthUsingAgentPreferIdentity(conn, sshState, selected.User, selected.IdentityFile); err == nil {
				f.Println("Authentication complete (agent).")
				if parsedArgs["test"] == "true" {
					f.Println("Test mode: Authentication successful, exiting before session start.")
					logDebug("Exiting after successful authentication in test mode.")
					return
				}

				startSession(conn, sshState)
				return
			} else {
				f.Printf("Agent auth not available or failed: %v\n", err)
			}

			// Try direct identity file
			if err := performKeybasedAuth(conn, sshState, selected.User, selected.IdentityFile); err != nil {
				f.Printf("Key-based auth with identity file failed: %v\n", err)
				// Try passphrase if the key might be encrypted
				f.Print("Enter key passphrase (leave blank to skip): ")
				passBytes, _ := term.ReadPassword(int(os.Stdin.Fd()))
				f.Println() // Newline after input
				pass := string(passBytes)
				if pass != "" {
					if err2 := performKeybasedAuthWithPassphrase(conn, sshState, selected.User, selected.IdentityFile, pass); err2 != nil {
						f.Printf("Key-based auth with passphrase failed: %v\n", err2)
					} else {

						if parsedArgs["test"] == "true" {
							f.Println("Test mode: Authentication successful, exiting before session start.")
							logDebug("Exiting after successful authentication in test mode.")
							return
						}

						f.Println("Authentication complete.")
						startSession(conn, sshState)
						return
					}
				}
			} else {
				f.Println("Authentication complete.")
				startSession(conn, sshState)
				return
			}
		}

		// Fallback to password auth
		f.Printf("Password authentication for %s@%s\n", selected.User, selected.Hostname)
		f.Print("Enter password: ")
		pwdBytes, _ := term.ReadPassword(int(os.Stdin.Fd()))
		f.Println() // Newline after input
		if err := performPasswordAuth(conn, sshState, selected.User, string(pwdBytes)); err != nil {
			f.Printf("Password auth failed: %v\n", err)
		} else {
			f.Println("Authentication complete.")
			startSession(conn, sshState)
		}

	} else {
		f.Println("FAILURE: Server rejected encryption or logic error.")
	}

}
