import socket
from Crypto.PublicKey import ECC
from crypto_utils import generate_keypair, derive_shared_key, encrypt, decrypt

def start_client():
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('127.0.0.1', 12345))

                # Generate and send public key
                private_key, public_key = generate_keypair()
                s.sendall(public_key.export_key(format="DER"))

                # Receive server's public key and derive shared key
                server_public_key_data = s.recv(1024)
                server_public_key = ECC.import_key(server_public_key_data)
                shared_key = derive_shared_key(private_key, server_public_key)

                # Messaging loop
                while True:
                    message = input("Client: ")
                    nonce, ciphertext, tag = encrypt(shared_key, message)
                    enc_data = len(nonce).to_bytes(1, 'big') + nonce + len(ciphertext).to_bytes(1, 'big') + ciphertext + tag
                    s.sendall(enc_data)

                    enc_data = s.recv(1024)
                    if not enc_data:
                        raise ConnectionAbortedError("Server disconnected")

                    nonce_length = enc_data[0]
                    nonce = enc_data[1:1+nonce_length]
                    ciphertext_length = enc_data[1+nonce_length]
                    ciphertext = enc_data[2+nonce_length:2+nonce_length+ciphertext_length]
                    tag = enc_data[2+nonce_length+ciphertext_length:]
                    server_message = decrypt(shared_key, nonce, ciphertext, tag)
                    print(f"Received from server: {server_message}")

        except ConnectionAbortedError:
            print("Primary Server for Chat Got Disconnected due to unknown reason, you might have to restart it")
            break

        except Exception as ex:
            if ex.errno == 61:  # Connection refused error
                print("Server unavailable. Switching to server mode...")
                # Logic to switch client to server mode here
            else:
                print(f"An unexpected error occurred: {ex}")
                break

if __name__ == "__main__":
    start_client()
