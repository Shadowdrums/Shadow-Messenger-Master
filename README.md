# shadowmsg

## Usage
1.	Run the Application: Execute the main function in application.py to start the server and client interaction.
2.	User Registration: Follow the prompts to register a new user by providing a username, password, and target IP address.
3.	User Login: Login with your username and password. Select or add a new IP address for communication.
4.	Secure Communication: The application will handle secure communication using Diffie-Hellman key exchange and AES encryption.

## API Documentation

### Application

#### Class: Application
#### Methods:
	- __init__(self, tcp_listener: TcpListener, client_connection: ClientConnection): Initializes the application with TCP listener and client connection.
	- run(self): Sets up the database, handles user input, and starts the TCP listener and client connection.

### DatabaseManager

#### Class: DatabaseManager
#### Methods:
	- setup_database(self): Sets up the database with required tables.
	- insert_user(self, user: User, encryption_handler: EncryptionHandler): Inserts a new user into the database.
	- store_key(self, username: str, key: bytes): Stores the encryption key for a user.
	- get_key(self, username: str) -> Optional[bytes]: Retrieves the encryption key for a user.
	- verify_user(self, username: str, password: str) -> bool: Verifies the user's credentials.
	- get_user_ips(self, username: str, encryption_handler: EncryptionHandler) -> List[str]: Retrieves the IP addresses associated with a user.
	- add_ip_for_user(self, username: str, ip: str, encryption_handler: EncryptionHandler): Adds a new IP address for a user.
	- insert_contact(self, username: str, contact_username: str, contact_ip: str): Inserts a new contact for a user.
	- get_contacts(self, username: str) -> List[tuple[str, str]]: Retrieves the contacts for a user.

### EncryptionHandler

#### Class: EncryptionHandler
#### Methods:
	- encrypt(self, message: str) -> bytes: Encrypts a message using AES encryption.
	- decrypt(self, encrypted_message: bytes) -> str: Decrypts an encrypted message using AES decryption.
### ProtocolMessage

#### Class: ProtocolMessage
#### Methods:
	- to_bytes(self, encryption_handler: EncryptionHandler) -> bytes: Converts the protocol message to bytes.
	- from_bytes(data: bytes, encryption_handler: EncryptionHandler) -> Optional["ProtocolMessage"]: Converts bytes to a protocol message.
	- hello_message(cls, username): Creates a "HELLO" message.
	- keep_alive_message(cls, username): Creates a "KEEP_ALIVE" message.
	- ack_message(cls, username): Creates an "ACK" message.
### ConnectionHandler

#### Class: ConnectionHandler
#### Methods:
	- handle_connection(self, conn: socket.socket, addr, encryption_handler: EncryptionHandler): Handles incoming connections and processes messages.
### DiffieHellmanKeyExchange

#### Class: DiffieHellmanKeyExchange
#### Methods:
	- perform_key_exchange(self, conn: socket.socket, addr, connection_handler: ConnectionHandler): Performs the Diffie-Hellman key exchange and establishes a secure connection.
### TcpListener

#### Class: TcpListener
#### Methods:
	- listen_tcp(self): Listens for incoming TCP connections and starts a new thread for each connection.
### IPResolver

#### Class: IPResolver
#### Methods:
	- resolve_ip(self, target_ip: str) -> str: Resolves the target IP address.
### UserInputHandler

#### Class: UserInputHandler
#### Methods:
	- get_user_input(self) -> tuple[str, str]: Handles user input for login and registration.
### Banner

#### Functions:
	- run_banner(txt: str = banner): Displays the banner.
License
This project is licensed under the MIT License. See the LICENSE file for details.
