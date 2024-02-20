from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes

def generate_mac(key, message):
    hmac = HMAC.new(key, message, SHA256)
    return hmac.digest()

def verify_mac(key, message, mac):
    hmac = HMAC.new(key, message, SHA256)
    try:
        hmac.verify(mac)
        return True
    except ValueError:
        return False

def encrypt_with_mac(key, plaintext):
    salsa_key = get_random_bytes(32)
    nonce = get_random_bytes(8)
    cipher = Salsa20.new(key=salsa_key, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    mac = generate_mac(key, ciphertext)
    return ciphertext, mac, nonce

def decrypt_with_mac(key, ciphertext, mac, nonce):
    if not verify_mac(key, ciphertext, mac):
        raise ValueError("MAC verification failed. The ciphertext may have been tampered with.")
    cipher = Salsa20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

key = get_random_bytes(16)  
plaintext = b'Hello, World! This is a secret message.'

ciphertext, mac, nonce = encrypt_with_mac(key, plaintext)
print("Ciphertext:", ciphertext.hex())
print("MAC:", mac.hex())
print("Nonce:", nonce.hex())


decrypted_text = decrypt_with_mac(key, ciphertext, mac, nonce)
print("Decrypted Text:", decrypted_text)


