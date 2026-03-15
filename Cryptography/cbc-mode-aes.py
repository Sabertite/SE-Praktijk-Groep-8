from base64 import b64decode
from Crypto.Cipher import AES

# Gebaseerd op jouw code uit '3 - ECB Mode AES.py'
def ECB_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

# Gebaseerd op jouw code uit '2 - binary XOR.py'
def repeating_key_xor(text, key):
    return bytes([text[i] ^ key[i % len(key)] for i in range(len(text))])

def CBC_decrypt(ciphertext, key, IV):
    """
    Decrypts a given ciphertext in CBC mode.
    """
    block_size = len(key) # Meestal 16 bytes voor AES [cite: 74]
    plaintext = b""
    prev_block = IV # We beginnen met de IV voor het eerste blok 

    # Loop door de ciphertext in stappen van de blokgrootte [cite: 95]
    for i in range(0, len(ciphertext), block_size):
        current_block = ciphertext[i:i + block_size]
        
        # Stap 1: Decrypt het huidige blok met ECB [cite: 101, 126]
        decrypted_block = ECB_decrypt(current_block, key)
        
        # Stap 2: XOR het resultaat met het vorige ciphertext blok (of IV) [cite: 89, 137]
        # Omdat de blokken even lang zijn, werkt repeating_key_xor perfect.
        plaintext_block = repeating_key_xor(decrypted_block, prev_block)
        
        plaintext += plaintext_block
        
        # Stap 3: Update het 'vorige blok' naar de huidige ciphertext voor de volgende ronde [cite: 122]
        prev_block = current_block

    return plaintext

# Laat dit blok code onaangetast & onderaan je code! [cite: 20]
a_ciphertext = b64decode('e8Fa/QnddxdVd4dsL7pHbnuZvRa4OwkGXKUvLPoc8ew=')
a_key = b'SECRETSAREHIDDEN'
a_IV = b'WE KNOW THE GAME'
assert CBC_decrypt(a_ciphertext, a_key, a_IV)[:18] == \
    b64decode('eW91IGtub3cgdGhlIHJ1bGVz')

print("Succes! De CBC decryptie werkt correct.")