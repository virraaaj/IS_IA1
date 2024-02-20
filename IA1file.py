
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes

def encrypt_file(key, input_file, output_file):
    cipher = Salsa20.new(key=key)
    with open(input_file, 'rb') as f_in:
        plaintext = f_in.read()
    ciphertext = cipher.encrypt(plaintext)
    with open(output_file, 'wb') as f_out:
        f_out.write(ciphertext)

def decrypt_file(key, input_file, output_file):
    cipher = Salsa20.new(key=key)
    with open(input_file, 'rb') as f_in:
        ciphertext = f_in.read()
    plaintext = cipher.decrypt(ciphertext)
    with open(output_file, 'wb') as f_out:
        f_out.write(plaintext)

key = get_random_bytes(32)  # 256-bit key
input_file = 'plaintext.txt'
encrypted_file = 'encrypted.txt'
decrypted_file = 'decrypted.txt'

# Encrypt the file
encrypt_file(key, input_file, encrypted_file)
print("File encrypted.")

# Decrypt the file
decrypt_file(key, encrypted_file, decrypted_file)
print("File decrypted.")
