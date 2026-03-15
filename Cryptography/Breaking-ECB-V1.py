from base64 import b64decode
from Crypto.Cipher import AES
from secrets import token_bytes

def pkcs7_pad(plaintext, blocksize):
    """
    Adds extra 'filler' bytes to the end of the text to make sure 
    it fits perfectly into the fixed-size blocks required by AES.
    """
    # Calculate how many extra bytes we need
    n = blocksize - len(plaintext) % blocksize
    # Add the filler (e.g., if we need 4 bytes, we add the number 4, four times)
    plaintext += (n * bytes([n]))
    return plaintext

def ECB_oracle(plaintext, key):
    """
    This acts like a 'black box'. It adds a secret message to your 
    input and encrypts the whole thing.
    """
    # Secret text is added to the end of your input
    plaintext += b64decode('U2F5IG5hIG5hIG5hCk9uIGEgZGFyayBkZXNlcnRlZCB3YXksIHNheSBuYSBuYQpUaGVyZSdzIGEgbGlnaHQgZm9yIHlvdSB0aGF0IHdhaXRzLCBpdCdzIG5hIG5hIG5hClNheSBuYSBuYYSBuYSwgc2F5IG5hIG5hCllvdSdyZSBub3QgYWxvbmUsIHNvIHN0YW5kIHVwLCBuYSBuYSBuYQpCZSBhIGhlcm8sIGJlIHRoZSByYWluYm93LCBhbmQgc2luZyBuYSBuYSBuYQpTYXkgbmEgbmEgbmE=')
    plaintext = pkcs7_pad(plaintext, len(key))
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

# Create a random secret key for this session
key = token_bytes(16)

def find_block_length():
    """
    Figures out how big the 'blocks' of the encryption are (usually 16 bytes).
    """
    i = 1
    while True:
        # Compare encryption results for two slightly different lengths
        c1 = ECB_oracle(b'A' * i, key)
        c2 = ECB_oracle(b'A' * (i + 1), key)
        
        common_length = 0
        for byte1, byte2 in zip(c1, c2):
            if byte1 == byte2:
                common_length += 1
            else:
                break
        
        # If the output starts matching, we've found the block size
        if common_length > 0:
            return common_length
        i += 1

def find_secret_text():
    """
    The 'Cracker' function. It guesses the secret text character by character.
    """
    block_length = find_block_length()
    
    # See how long the whole message is
    empty_encryption = ECB_oracle(b'', key)
    total_length = len(empty_encryption)
    
    found_secret = b''
    print("Starting the crack. This may take a moment...")
    
    for i in range(total_length):
        # We use 'padding' to shift the secret text so that only one 
        # unknown character falls into the block we are looking at.
        pad_len = (block_length - 1) - (i % block_length)
        padding = b'A' * pad_len
        
        block_start = (i // block_length) * block_length
        block_end = block_start + block_length
        
        # Get the 'target' block we want to crack
        target_ciphertext = ECB_oracle(padding, key)
        target_block = target_ciphertext[block_start:block_end]
        
        # Try all 256 possible byte values (0-255) to see which one matches
        for j in range(256):
            test_byte = bytes([j])
            # Our test: padding + what we already know + our new guess
            test_plaintext = padding + found_secret + test_byte
            test_ciphertext = ECB_oracle(test_plaintext, key)
            test_block = test_ciphertext[block_start:block_end]
            
            # If the encrypted block matches our target, we found a character!
            if test_block == target_block:
                found_secret += test_byte
                print(f"Cracked so far: {found_secret.decode('ascii', errors='ignore')}")
                break 
                
    return found_secret

# Run the script
final_message = find_secret_text()
print("\n--- SUCCESS! THE SECRET TEXT IS: ---")
print(final_message.decode('ascii', errors='ignore'))