from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes

def encrypt_message(key, plaintext):

    nonce = get_random_bytes(8)

    cipher = Salsa20.new(key=key, nonce=nonce)

    ciphertext = cipher.encrypt(plaintext)

    return ciphertext, nonce

def decrypt_message(key, ciphertext, nonce):
  
    cipher = Salsa20.new(key=key, nonce=nonce)

    plaintext = cipher.decrypt(ciphertext)

    
    return plaintext


key = get_random_bytes(32)  
plaintext = b'Hello, World! This is a secret message.'

ciphertext, nonce = encrypt_message(key, plaintext)
print("Ciphertext:", ciphertext.hex())

decrypted_text = decrypt_message(key, ciphertext, nonce)
print("Decrypted Text:", decrypted_text.decode('utf-8'))
