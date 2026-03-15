from base64 import b64encode

def fixed_length_xor(text, key):
    """
    Performs a binary XOR of two equal-length strings. 
    """
    # XOR elke byte van 'text' met de corresponderende byte van 'key'
    return bytes([t ^ k for t, k in zip(text, key)])

# Laat deze asserts onaangetast!
assert type(fixed_length_xor(b'foo',b'bar')) == bytes
assert b64encode(fixed_length_xor(b'foo',b'bar')) == b'BA4d'

def repeating_key_xor(text, key):
    """Takes two bytestrings and XORs them, returning a bytestring.
    Extends the key to match the text length.
    """
    # Herhaal de key met de modulo operator (%) terwijl we door de tekst lopen
    return bytes([text[i] ^ key[i % len(key)] for i in range(len(text))])

# Laat deze asserts onaangetast!
assert type(repeating_key_xor(b'all too many words',b'bar')) == bytes
assert b64encode(repeating_key_xor(b'all too many words',b'bar'))\
   == b'Aw0eQhUdDUEfAw8LQhYdEAUB'