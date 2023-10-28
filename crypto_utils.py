from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

def generate_keypair():
    private_key = ECC.generate(curve='P-256')
    return private_key, private_key.public_key()

def derive_shared_key(private_key, peer_public_key):
    shared_secret = private_key.d * peer_public_key.pointQ
    salt = b'secure_messaging_salt'  # Ideally, this should be a random value for each derivation.
    shared_key = HKDF(master=shared_secret.x.to_bytes(), salt=salt, key_len=32, hashmod=SHA256)
    return shared_key



def encrypt(shared_key, plaintext):
    cipher = AES.new(shared_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return (cipher.nonce, ciphertext, tag)

def decrypt(shared_key, nonce, ciphertext, tag):
    cipher = AES.new(shared_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
