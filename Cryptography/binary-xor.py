from base64 import b64encode

def fixed_length_xor(text, key):
    """
    Mixes two pieces of data (text and key) that are the exact same length.
    """
    # Go through both the text and key, mixing every character one by one
    return bytes([t ^ k for t, k in zip(text, key)])

assert type(fixed_length_xor(b'foo',b'bar')) == bytes
assert b64encode(fixed_length_xor(b'foo',b'bar')) == b'BA4d'

def repeating_key_xor(text, key):
    """
    Mixes text with a key. If the key is shorter than the text, 
    the key repeats itself until the text is finished.
    """
    # The '%' (modulo) makes the key start over from the beginning if it runs out
    return bytes([text[i] ^ key[i % len(key)] for i in range(len(text))])

assert type(repeating_key_xor(b'all too many words',b'bar')) == bytes
assert b64encode(repeating_key_xor(b'all too many words',b'bar'))\
   == b'Aw0eQhUdDUEfAw8LQhYdEAUB'