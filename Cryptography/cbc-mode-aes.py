from base64 import b64decode
from Crypto.Cipher import AES

def ECB_decrypt(ciphertext, key):
    """Basic AES decryption (used as a building block for CBC)."""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def repeating_key_xor(text, key):
    """Simple XOR helper to mix data."""
    return bytes([text[i] ^ key[i % len(key)] for i in range(len(text))])

def CBC_decrypt(ciphertext, key, IV):
    """
    Decrypts data that was locked using Cipher Block Chaining (CBC).
    """
    block_size = len(key) 
    plaintext = b""
    prev_block = IV # CBC starts with an 'Initialization Vector' (IV)

    # Process the data block by block
    for i in range(0, len(ciphertext), block_size):
        current_block = ciphertext[i:i + block_size]
        
        # 1. Decrypt the block normally
        decrypted_block = ECB_decrypt(current_block, key)
        
        # 2. XOR it with the previous block (the 'chaining' part)
        plaintext_block = repeating_key_xor(decrypted_block, prev_block)
        
        plaintext += plaintext_block
        
        # 3. Remember the current ciphertext block to use for the NEXT block
        prev_block = current_block

    return plaintext

# Verification code
a_ciphertext = b64decode('e8Fa/QnddxdVd4dsL7pHbnuZvRa4OwkGXKUvLPoc8ew=')
a_key = b'SECRETSAREHIDDEN'
a_IV = b'WE KNOW THE GAME'
assert CBC_decrypt(a_ciphertext, a_key, a_IV)[:18] == \
    b64decode('eW91IGtub3cgdGhlIHJ1bGVz')

print("Success! CBC decryption is working correctly.")