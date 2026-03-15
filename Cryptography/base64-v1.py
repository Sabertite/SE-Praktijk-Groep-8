import base64

def string_to_b64(asciiString):
    """
    Turns a normal piece of text into a Base64 encoded version.
    """
    # Step 1: Turn the text into raw computer data (bytes)
    byte_data = asciiString.encode('ascii')
    
    # Step 2: Convert those raw bytes into the Base64 format
    b64String = base64.b64encode(byte_data)

    return b64String

# These 'asserts' check if the code works correctly. Do not change them!
assert type(string_to_b64("foo")) == bytes
assert string_to_b64("Hello World") == b'SGVsbG8gV29ybGQ='

def b64_to_string(b64String):
    """
    Takes a Base64 encoded piece of data and turns it back into readable text.
    """
    # Step 1: Decode the Base64 data back into raw bytes
    decoded_bytes = base64.b64decode(b64String)
    
    # Step 2: Turn those raw bytes back into a readable string (text)
    asciiString = decoded_bytes.decode('ascii')

    return asciiString

# These checks ensure the decoding works as expected.
assert type(b64_to_string("SGVsbG8gV29ybGQ=")) == str
assert b64_to_string("SGVsbG8gV29ybGQ=") == "Hello World"