import base64

def string_to_b64(asciiString):
    """
    Converts a given ASCII-string to its b64-encoded equivalent.
    Parameters
    ----------
    asciiString : string
        string to be converted

    Returns
    -------
    bytes
        b64-encoded bytes-object representing the original string
    """
    # Convert the string to a bytes object using ASCII encoding
    byte_data = asciiString.encode('ascii')
    
    # Encode the raw bytes into base64 format
    b64String = base64.b64encode(byte_data)

    return b64String

# Laat deze asserts onaangetast!
assert type(string_to_b64("foo")) == bytes
assert string_to_b64("Hello World") == b'SGVsbG8gV29ybGQ='

def b64_to_string(b64String):
    """
    Converts a given b64-string to its ASCII equivalent.

    Parameters
    ----------
    b64String : bytes
        b64-encoded bytesobject to be converted

    Returns
    -------
    string
        ASCII string
    """
    # Decode the base64 data back to standard bytes
    decoded_bytes = base64.b64decode(b64String)
    
    # Convert the decoded bytes back into a readable string
    asciiString = decoded_bytes.decode('ascii')

    return asciiString

# Laat deze asserts onaangetast!
assert type(b64_to_string("SGVsbG8gV29ybGQ=")) == str
assert b64_to_string("SGVsbG8gV29ybGQ=") == "Hello World"