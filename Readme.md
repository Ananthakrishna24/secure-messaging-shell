# 🛡️ Encrypted Chat Application

An encrypted chat application built using Python's `socket` module and `Crypto` library. It allows two parties, a server and a client, to exchange encrypted messages over a TCP connection.

## 🌟 Features

- 🛡️ Secure: Uses ECC (Elliptic Curve Cryptography) for key exchange and AES-GCM for encryption.
- 🔄 Role Reversal: If the server disconnects, the client becomes the server, waiting for the original server to reconnect.
- 💡 Graceful Handling: Client retries connection and server awaits a return, ensuring seamless communication.

## 🚀 Getting Started

### Prerequisites

- **Python 3.x**
- **pycryptodome** library

    ```bash
    pip install pycryptodome
    ```

### Installation

1. **Clone the Repository**

    ```bash
    git clone https://github.com/Ananthakrishna24/secure-messaging-shell.git
    cd encrypted-chat
    ```

2. **Server Setup**

    Run the server script:

    ```bash
    python server.py
    ```

    This will start the server, waiting for client connections.

3. **Client Setup**

    If the server is on a different machine, modify the IP address in the client script. Replace `'127.0.0.1'` with the server machine's IP address. Then, run:

    ```bash
    python client.py
    ```

    The client will now connect to the server, and you can start chatting!

## 📞 Using the Chat Application

- **Messaging**: Just type your message into the console and press enter.
- **Disconnections**: 
  - Client: If disconnected, it will try to reconnect.
  - Server: Will notify the user and wait for the client to return.

## 🌐 Networking

The default IP address `'127.0.0.1'` is for localhost. To use the application across different machines:
- Set the server's IP address in the client script to the actual IP of the server machine.
- Ensure firewalls aren't blocking connections on port `12345`.

## 🔐 Security Considerations

While the application focuses on secure message transmission, always ensure:
- You're aware of potential vulnerabilities when deploying on a public network.
- This app is for educational purposes. Exercise caution in production environments.

## 🤝 Contribution

Feel free to fork the project, submit issues, and send pull requests. Your feedback and contributions are welcomed!
