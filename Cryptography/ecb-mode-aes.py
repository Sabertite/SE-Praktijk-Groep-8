from base64 import b64decode
from Crypto.Cipher import AES

def ECB_decrypt(ciphertext, key):
    """
    Takes encrypted data and a 16-byte key to return the original message.
    """
    # Create the AES tool in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Decrypt and return the result
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# Verification check
ciphertext = b64decode('86ueC+xlCMwpjrosuZ+pKCPWXgOeNJqL0VI3qB59SSY=')
key = b'SECRETSAREHIDDEN'
assert ECB_decrypt(ciphertext, key)[:28] == \
    b64decode('SGFzdCBkdSBldHdhcyBaZWl0IGZ1ciBtaWNoPw==')

# Example: Opening a file, decoding it from Base64, and then decrypting it
try:
    with open('file3.txt', 'r') as file:
        b64_file_content = file.read()
        
    # Convert Base64 text to raw encrypted bytes
    encrypted_bytes = b64decode(b64_file_content)

    # Unlock the secret message
    decrypted_message = ECB_decrypt(encrypted_bytes, key)
    print("Decrypted message:")
    print(decrypted_message.decode('ascii'))
except FileNotFoundError:
    print("Note: 'file3.txt' not found, skipping file decryption demo.")