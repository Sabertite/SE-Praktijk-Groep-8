from base64 import b64decode
from Crypto.Cipher import AES

def ECB_decrypt(ciphertext, key):
    """Accepts a ciphertext in byte-form,
    as well as 16-byte key, and returns 
    the corresponding plaintext.

    Parameters
    ----------
    ciphertext : bytes
        ciphertext to be decrypted
    key : bytes
        key to be used in decryption

    Returns
    -------
    bytes
        decrypted plaintext
    """
    # Maak een AES cipher object aan in ECB mode met de gegeven key
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Decrypt de ciphertext
    plaintext = cipher.decrypt(ciphertext)

    return plaintext

# Laat deze asserts onaangetast & onderaan je code!
ciphertext = b64decode('86ueC+xlCMwpjrosuZ+pKCPWXgOeNJqL0VI3qB59SSY=')
key = b'SECRETSAREHIDDEN'
assert ECB_decrypt(ciphertext, key)[:28] == \
    b64decode('SGFzdCBkdSBldHdhcyBaZWl0IGZ1ciBtaWNoPw==')

# file3.txt ontsleutelen
with open('file3.txt', 'r') as file:
    b64_file_content = file.read()
    
# Decodeer de base64 tekst naar bytes
encrypted_bytes = b64decode(b64_file_content)

# Decrypt en print het resultaat
decrypted_message = ECB_decrypt(encrypted_bytes, key)
print(decrypted_message.decode('ascii'))