# Shadow-Messenger-Master
this is a 256bit AES CFB end to end encrypted messenger over ip

# Shadow Messenger Master

Welcome to Shadow Messenger, a simple yet secure TCP-based messaging application. This program allows you to send and receive encrypted messages over the network using AES encryption.

## Features

- **AES Encryption:** Messages are encrypted using AES in CFB mode for secure communication.
- **User Identification:** Messages include the sender's username to identify who sent each message.
- **Keep-Alive Mechanism:** Maintains the connection alive by sending keep-alive messages periodically.
- **Multi-threaded Server:** The server can handle multiple simultaneous connections.

## Prerequisites

- Python 3.x
- `pycryptodome` library

## Installation

1. **Clone the Repository:**
   ```sh
   git clone https://github.com/shadowdrums/Shadow-Messenger-Master.git

   cd Shadow-Messenger-Master

## Install Dependencies:

pip install pycryptodome

# Usage

##Running the Server

To start the server, simply run the following command:

python Shadow-Messenger-Master.py

The server will start listening on port 13377.

## Running the Client:

To connect to the server and send messages, run the following command:

python Shadow-Messenger-Master.py

Follow the prompts to enter your username and the IP address of the target machine.

# Code Overview

## Key Functions:

generate_key(): Generates a 256-bit AES key and saves it to master.key if it doesn't already exist.
load_key(): Loads the AES key from master.key.
ProtocolMessage Class:
to_bytes(key): Serializes and encrypts the message.
from_bytes(data, key): Deserializes and decrypts the message.
hello_message(username): Generates a hello message.
keep_alive_message(username): Generates a keep-alive message.
ack_message(username): Generates an acknowledgment message.
send_tcp_message(sock, key, username): Connects to the server and sends encrypted messages.
handle_connection(conn, addr, key): Handles the communication with the client, decrypts incoming messages, and displays them.
send_keep_alive(sock, key, username): Sends keep-alive messages to maintain the connection.
resolve_ip(target_ip): Resolves the target IP address.
user_input_generator(): Generates user input for the client.
main_loop(key): Main loop for the client to send messages.
main(): Starts the server and the client main loop.

## Directory Structure:

shadow-messenger/
├── master.key              # AES key file
├── ip.txt                  # File to store username and target IP
├── received_messages.txt   # File to store received messages
├── Shadow-Messenger-Master.py # Main program file
└── README.md               # This readme file

# Troubleshooting

## Common Errors:

Connection Timeout: Ensure that the server is running and reachable. The client will attempt to reconnect if it fails to connect initially.
Decryption Failed: Ensure that both the server and client are using the same AES key stored in master.key.
Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments:

Special Thanks to DJ Stomp for helping with this project

Inspired by the need for simple yet secure messaging over the network.
Utilizes the pycryptodome library for encryption and decryption.

Thank you for using Shadow Messenger! We hope it serves your needs well.



