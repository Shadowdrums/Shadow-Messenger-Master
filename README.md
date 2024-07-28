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
- 1. Select 1. or 2. "Login" or "register" when prompted.
- 2. Enter your username.
- 3. Enter your password.
- 4. Select the IP address for communication or add a new one if needed.

## Running with Poetry

Install dependencies and set up the environment using poetry:

Copy code
```sh
poetry add pycryptodome

poetry add homegrowndhe

poetry add appdirs

poetry install

poetry build

```
## Run the application using poetry:

### Copy code
```sh
poetry run python -m shadowmsg
# Follow prompts for registration or login
# Once logged in, you can start sending and receiving secure messages
```
Follow the same steps as above for login or registration and selecting an IP address.

The server will start listening on port 21337 for incoming connections.

### Secure Communication

After logging in, you can send and receive messages securely. The application will handle the Diffie-Hellman key exchange and AES encryption automatically.

# How It Works

### Diffie-Hellman Key Exchange with HKDF

Diffie-Hellman (DH) Key Exchange is a method used to securely exchange cryptographic keys over a public channel. Here’s how it works in the context of Shadow Messenger:
```
Parameter Generation: Both clients agree on a large prime number 
𝑝
p and a base 
𝑔
g (a generator). These parameters can be public.

Private Key Generation: Each client generates a private key 
𝑎
a and 
𝑏
b, which are large random numbers.
```
Public Key Generation: Using the private keys, each client generates their public keys:

Client 1 generates 
```
𝐴
=
𝑔
𝑎
m
o
d
 
 
𝑝
A=g 
a
 modp
```
Client 2 generates 
```
𝐵
=
𝑔
𝑏
m
o
d
 
 
𝑝
B=g 
b
 modp
Exchange Public Keys: The clients exchange their public keys 
𝐴
A and 
𝐵
B.
```
Shared Secret Calculation: Each client uses their private key and the other client’s public key to compute the shared secret:

Client 1 computes 
```
𝑆
=
𝐵
𝑎
m
o
d

 
𝑝
S=B 
a
 modp
```

Client 2 computes 
```
𝑆
=
𝐴
𝑏
m
o
d
 
 
𝑝
S=A 
b
 modp
```

The computed shared secret 
```
𝑆
S is the same for both clients and is not transmitted over the network, making it secure.
```

HMAC-based Extract-and-Expand Key Derivation Function (HKDF) is used to derive a strong encryption key from the shared secret. Here’s how HKDF is used:

Extract: The shared secret 
```
𝑆
S is used as input to an HMAC function along with an optional salt to produce a pseudorandom key (PRK).
```
Expand: The PRK is then expanded into several additional pseudorandom keys by applying the HMAC function again along with some contextual information.

The final output is a cryptographically strong key derived from the shared secret.


### AES CFB Mode

Advanced Encryption Standard (AES) in Cipher Feedback (CFB) mode is used to encrypt and decrypt messages. Here’s why AES CFB mode is suitable for this application:

Stream Cipher: CFB mode turns a block cipher (AES) into a stream cipher, which means it can encrypt data of any length, making it flexible for varying message sizes.

No Padding: Unlike some other modes of operation, CFB mode does not require padding the plaintext to a multiple of the block size.

Error Propagation: Errors in one block affect only a few subsequent blocks, not the entire message.

### How AES CFB Mode Works:

The encryption process uses an initialization vector (IV) along with the secret key. The IV ensures that the same plaintext encrypted multiple times will produce different ciphertexts.
The plaintext is XORed with the output of the AES encryption of the IV (or previous ciphertext block), resulting in the ciphertext.
For decryption, the ciphertext is XORed with the output of the AES encryption of the IV (or previous ciphertext block) to retrieve the plaintext.
Why This Encryption Practice is Good for P2P Over IPv4
Security: The combination of Diffie-Hellman key exchange and AES encryption provides strong security guarantees. The DH key exchange ensures that the key is securely exchanged even over an insecure channel. AES in CFB mode provides confidentiality and data integrity.

Flexibility: CFB mode does not require padding and can handle messages of arbitrary length, making it suitable for P2P communication where message sizes can vary.

Efficiency: Both DH key exchange and AES encryption are efficient and can be performed quickly, ensuring real-time communication is feasible.

Simplicity: The protocol is straightforward to implement and understand, reducing the risk of security vulnerabilities due to implementation errors.

Compatibility: IPv4 is the most widely used version of the Internet Protocol. This setup works seamlessly over IPv4, making it widely applicable and easy to deploy without requiring specialized infrastructure.

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

# MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

**Disclaimer**: The software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software.

# Disclaimer

ShadowDrums and ShadowTEAM members will not be held liable for any misuse of this source code, program, or software. It is the responsibility of the user to ensure that their use of this software complies with all applicable laws and regulations. By using this software, you agree to indemnify and hold harmless Shadowdrums and ShadowTEAM members from any claims, damages, or liabilities arising from your use or misuse of the software.

### Authors

- Shadowdrums
- DJ Stomp

This was a Team project to make a secure P2P messenger over public channels
