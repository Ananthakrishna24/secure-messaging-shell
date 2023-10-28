import socket
from Crypto.PublicKey import ECC
from crypto_utils import generate_keypair, derive_shared_key, encrypt, decrypt

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 12345))
        s.listen()
        print('Waiting for connection...')
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)

            # Generate and send public key
            private_key, public_key = generate_keypair()
            conn.sendall(public_key.export_key(format="DER"))

            # Receive client's public key and derive shared key
            client_public_key_data = conn.recv(1024)
            client_public_key = ECC.import_key(client_public_key_data)
            shared_key = derive_shared_key(private_key, client_public_key)

            # Messaging loop
            while True:
                enc_data = conn.recv(1024)
                nonce_length = enc_data[0]
                nonce = enc_data[1:1+nonce_length]
                ciphertext_length = enc_data[1+nonce_length]
                ciphertext = enc_data[2+nonce_length:2+nonce_length+ciphertext_length]
                tag = enc_data[2+nonce_length+ciphertext_length:]
                message = decrypt(shared_key, nonce, ciphertext, tag)
                print(f"Received: {message}")

                # Server's turn to send a message
                server_message = input("Server: ")
                nonce, ciphertext, tag = encrypt(shared_key, server_message)
                enc_data = len(nonce).to_bytes(1, 'big') + nonce + len(ciphertext).to_bytes(1, 'big') + ciphertext + tag
                conn.sendall(enc_data)



if __name__ == "__main__":
    start_server()
