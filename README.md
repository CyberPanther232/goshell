# GoShell

![GoShell Logo](goshell_logo.png)

**GoShell** is a lightweight, educational SSH client implementation written in Go.

## ⚠️ Disclaimer: Educational Use Only

This project is a **Proof of Concept (PoC)** and a learning exercise to understand the internal workings of the Secure Shell (SSH) protocol (RFC 4253).

**It is NOT intended for production environments.**

* **Security:** While it implements standard cryptographic primitives (AES-CTR, HMAC-SHA256, ECDH, RSA/Ed25519/ECDSA), it has not been audited and may contain side-channel vulnerabilities or implementation flaws compared to battle-tested clients like OpenSSH.
* **Features:** It supports a subset of SSH functionality (interactive shells, basic key authentication) and lacks many advanced features (port forwarding, X11 forwarding, comprehensive config parsing).

## Features

* **Interactive Shell:** Connect to remote servers and use an interactive terminal (supports raw mode and basic PTY requests).
* **Key Exchange:** Implements `ecdh-sha2-nistp256`.
* **Encryption:** Uses `aes128-ctr` for encryption and `hmac-sha2-256` for integrity.
* **Authentication:**
  * Password Authentication
  * Public Key Authentication (RSA, Ed25519, ECDSA)
  * SSH Agent Support
  * Encrypted Private Keys (Passphrase support)
* **Configuration:** Simple file-based configuration.

## Installation

```bash
go get github.com/CyberPanther232/goshell
go build
```

## Configuration

GoShell looks for a `goshell.conf` file in the current directory. The format is similar to a standard SSH config file. By default, GoShell uses password based authentication unless the "KeybasedAuthentication" value is listed within the configuration file like in the example below:

**Example `goshell.conf`:**

```ssh
Host myserver
Hostname 192.168.1.100
Port 22
User admin
KeybasedAuthentication yes
IdentityFile C:\Users\User\.ssh\id_rsa

Host fallback
Hostname example.com
Port 2222
User dev
```

## Usage

1. Create your `goshell.conf`.
2. Run the executable:
   ```bash
   ./goshell
   ```
3. Select a host from the menu.
4. Enter your password or passphrase if prompted.

## License

[MIT License](LICENSE)
