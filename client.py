import socket
from crypto_utils import generate_keypair, derive_shared_key, encrypt, decrypt
from Crypto.PublicKey import ECC
import time

def try_reconnect():
    attempts = 50
    while attempts > 0:
        print("Attempting to reconnect...")
        time.sleep(5)  # Sleep for 5 seconds before trying
        try:
            start_client()
            return
        except socket.timeout:
            print(f"Reconnection attempt failed. {attempts - 1} attempts remaining.")
            attempts -= 1
        except Exception as e:
            print(f"Error during reconnection: {e}. {attempts - 1} attempts remaining.")
            attempts -= 1
    print("Max reconnection attempts reached. Exiting client.")
    exit()

def start_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('127.0.0.1', 12345))
        
        private_key, public_key = generate_keypair()
        s.sendall(public_key.export_key(format="DER"))

        server_public_key_data = s.recv(1024)
        server_public_key = ECC.import_key(server_public_key_data)
        shared_key = derive_shared_key(private_key, server_public_key)

        # Client initially waits for a message from the server
        enc_data = s.recv(1024)
        nonce_length = enc_data[0]
        nonce = enc_data[1:1+nonce_length]
        ciphertext_length = enc_data[1+nonce_length]
        ciphertext = enc_data[2+nonce_length:2+nonce_length+ciphertext_length]
        tag = enc_data[2+nonce_length+ciphertext_length:]
        server_message = decrypt(shared_key, nonce, ciphertext, tag)
        print(f"Received from server: {server_message}")

        while True:
            try:
                message = input("Client: ")
                nonce, ciphertext, tag = encrypt(shared_key, message)
                enc_data = len(nonce).to_bytes(1, 'big') + nonce + len(ciphertext).to_bytes(1, 'big') + ciphertext + tag
                s.sendall(enc_data)

                enc_data = s.recv(1024)
                nonce_length = enc_data[0]
                nonce = enc_data[1:1+nonce_length]
                ciphertext_length = enc_data[1+nonce_length]
                ciphertext = enc_data[2+nonce_length:2+nonce_length+ciphertext_length]
                tag = enc_data[2+nonce_length+ciphertext_length:]
                server_message = decrypt(shared_key, nonce, ciphertext, tag)
                print(f"Received from server: {server_message}")

            except ConnectionAbortedError:
                print("Lost connection to the server. Trying to reconnect...")
                try_reconnect()

            except Exception as ex:
                print(f"Error in communication: {ex}")
                break

if __name__ == "__main__":
    start_client()