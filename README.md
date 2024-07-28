# Shadow Messenger Master

## Overview

Shadow Messenger is a secure peer-to-peer (P2P) messaging application that uses 256-bit AES CFB encryption for message security and Diffie-Hellman key exchange with HKDF for secure key generation. This ensures that your communications are private and secure.

## Features

- **256-bit AES CFB Encryption**: Secure messages with Advanced Encryption Standard (AES) in Cipher Feedback (CFB) mode.
- **Diffie-Hellman Key Exchange with HKDF**: Securely generate shared secrets and derive encryption keys using HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
- **User Authentication**: User registration and login with password hashing.
- **Persistent Storage**: Store user data and keys securely in a SQLite database.
- **Automatic IP Resolution**: Resolve target IP addresses automatically.
- **Internal and External Connections**: Support for both internal network and external internet connections.

## Installation

### Prerequisites

- Python 3.6+
- Required Python packages (listed in `requirements.txt`)

### Installing Required Packages

You can install the required packages using `pip`:

```sh
pip install -r requirements.txt
```

### Cloning the Repository

Clone the repository to your local machine:

```sh
https://github.com/Shadowdrums/Shadow-Messenger-Master.git
cd Shadow-Messenger-Master
```

### Usage

```sh
python -m shadowmsg
# Follow prompts for registration or login
# Once logged in, you can start sending and receiving secure messages
```
- 1. Select "1./2. Login"/"register" when prompted.
- 2. Enter your username.
- 3. Enter your password.
- 4. Select the IP address for communication or add a new one if needed.

The server will start listening on port 21337 for incoming connections.

### Secure Communication

After logging in, you can send and receive messages securely. The application will handle the Diffie-Hellman key exchange and AES encryption automatically.

### How It Works

AES CFB Encryption
The Advanced Encryption Standard (AES) in Cipher Feedback (CFB) mode is used for encrypting and decrypting messages. CFB mode is suitable for stream encryption and allows encryption of variable-length data.

Diffie-Hellman Key Exchange with HKDF
Diffie-Hellman (DH) key exchange is used to securely generate a shared secret between two parties. This shared secret is then used to derive a strong encryption key using HMAC-based Extract-and-Expand Key Derivation Function (HKDF).

### API Documentation

## Application

# Class: Application
# Methods:

- `__init__(self, tcp_listener: TcpListener, client_connection: ClientConnection): Initializes the application with TCP listener and client connection.`

- `run(self): Sets up the database, handles user input, and starts the TCP listener and client connection.
  `

### DatabaseManager

## Class: DatabaseManager
# Methods:

- `setup_database(self): Sets up the database with required tables.`
- `insert_user(self, user: User, encryption_handler: EncryptionHandler): Inserts a new user into the database.`
- `store_key(self, username: str, key: bytes): Stores the encryption key for a user.`
- `get_key(self, username: str) -> Optional[bytes]: Retrieves the encryption key for a user.`
- `verify_user(self, username: str, password: str) -> bool: Verifies the user's credentials.`
- `get_user_ips(self, username: str, encryption_handler: EncryptionHandler) -> List[str]: Retrieves the IP addresses associated with a user.`
- `add_ip_for_user(self, username: str, ip: str, encryption_handler: EncryptionHandler): Adds a new IP address for a user.`
- `insert_contact(self, username: str, contact_username: str, contact_ip: str): Inserts a new contact for a user.`
- `get_contacts(self, username: str) -> List[tuple[str, str]]: Retrieves the contacts for a user.`
  

### EncryptionHandler

## Class: EncryptionHandler
# Methods:

- `encrypt(self, message: str) -> bytes: Encrypts a message using AES encryption.`
- `decrypt(self, encrypted_message: bytes) -> str: Decrypts an encrypted message using AES decryption.`
- `ProtocolMessage`


### Class: ProtocolMessage

## Methods:

- `to_bytes(self, encryption_handler: EncryptionHandler) -> bytes: Converts the protocol message to bytes.`
- `from_bytes(data: bytes, encryption_handler: EncryptionHandler) -> Optional["ProtocolMessage"]: Converts bytes to a protocol message.`
- `hello_message(cls, username): Creates a "HELLO" message.`
- `keep_alive_message(cls, username): Creates a "KEEP_ALIVE" message.`
- `ack_message(cls, username): Creates an "ACK" message.`


### ConnectionHandler

## Class: ConnectionHandler
# Methods:

- `handle_connection(self, conn: socket.socket, addr, encryption_handler: EncryptionHandler): Handles incoming connections and processes - messages.`

### DiffieHellmanKeyExchange

## Class: DiffieHellmanKeyExchange
# Methods:

- `perform_key_exchange(self, conn: socket.socket, addr, connection_handler: ConnectionHandler): Performs the Diffie-Hellman key exchange and establishes a secure connection.`

### TcpListener

## Class: TcpListener
# Methods:

- `listen_tcp(self): Listens for incoming TCP connections and starts a new thread for each connection.`


### IPResolver

## Class: IPResolver
# Methods:

- `resolve_ip(self, target_ip: str) -> str: Resolves the target IP address.`


### UserInputHandler

## Class: UserInputHandler
# Methods:

- `get_user_input(self) -> tuple[str, str]: Handles user input for login and registration.`


### MessageSender

## Class: MessageSender
# Methods:

- `send_keep_alive(self, sock: socket.socket, username: str, encryption_handler: EncryptionHandler): Sends keep-alive messages to maintain the connection.`
- `send_tcp_message(self, sock: socket.socket, username: str, encryption_handler: EncryptionHandler): Sends a message over TCP.`


### ClientConnection

## Class: ClientConnection
# Methods:

- `connect_and_communicate(self, username: str, target_ip: str): Connects to a server and handles secure communication.`

### Troubleshooting

## Connection Issues

- `Server Availability: Ensure that the server is running and accessible from the client machine.`
- `Firewall Settings: Verify that firewall settings on both the client and server allow traffic on the specified port.`
- `Port Forwarding: If the server is behind a router, configure port forwarding to allow external connections on the specified port.`
- `Network Configuration: Ensure both client and server are correctly configured to communicate over the network.`


### Database Issues

- `Permissions: Ensure the script has permission to create and write to the database file in the current working directory.`
- `Database File: Verify that the database file user_data.db exists and is accessible. The script should create it if it does not exist.`

### Authors

- Shadowdrums
- DJ Stomp

This was a Team project to make a secure P2P messenger over public channels
