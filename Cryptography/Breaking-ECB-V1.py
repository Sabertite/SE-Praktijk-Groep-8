from base64 import b64decode
from Crypto.Cipher import AES
from secrets import token_bytes

def pkcs7_pad(plaintext, blocksize):
    """Appends the plaintext with n bytes,
    making it an even multiple of blocksize.
    Byte used for appending is byteform of n.

    Parameters
    ----------
    plaintext : bytes
        plaintext to be appended
    blocksize : int
        blocksize to conform to

    Returns
    -------
    plaintext : bytes
        plaintext appended with n bytes
    """

    # Determine how many bytes to append
    n = blocksize - len(plaintext)%blocksize
    # Append n*(byteform of n) to plaintext
    # n is in a list as bytes() expects iterable
    plaintext += (n*bytes([n]))
    return plaintext

def ECB_oracle(plaintext, key):
    """Appends a top-secret identifier to the plaintext
    and encrypts it under AES-ECB using the provided key.

    Parameters
    ----------
    plaintext : bytes
        plaintext to be encrypted
    key : bytes
        16-byte key to be used in decryption

    Returns
    -------
    ciphertext : bytes
        encrypted plaintext
    """
    plaintext += b64decode('U2F5IG5hIG5hIG5hCk9uIGEgZGFyayBkZXNlcnRlZCB3YXksIHNheSBuYSBuYSBuYQpUaGVyZSdzIGEgbGlnaHQgZm9yIHlvdSB0aGF0IHdhaXRzLCBpdCdzIG5hIG5hIG5hClNheSBuYSBuYSBuYSwgc2F5IG5hIG5hIG5hCllvdSdyZSBub3QgYWxvbmUsIHNvIHN0YW5kIHVwLCBuYSBuYSBuYQpCZSBhIGhlcm8sIGJlIHRoZSByYWluYm93LCBhbmQgc2luZyBuYSBuYSBuYQpTYXkgbmEgbmEgbmE=')
    plaintext = pkcs7_pad(plaintext, len(key))
    cipher = cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

# Genereer een willekeurige key
key = token_bytes(16)

#####################################
###  schrijf hieronder jouw code  ###
### verander code hierboven niet! ###
#####################################
#5a
def find_block_length():
    """Finds the block length used by the ECB oracle.

    Returns
    -------
    blocksize : integer
        blocksize used by ECB oracle
    """
    # We beginnen met een padding van 1 byte en hogen dit steeds op
    i = 1
    
    while True:
        # Vraag de ciphertext op voor lengte i en lengte i+1
        c1 = ECB_oracle(b'A' * i, key)
        c2 = ECB_oracle(b'A' * (i + 1), key)
        
        # Tel hoeveel bytes aan het begin exact hetzelfde zijn
        common_length = 0
        for byte1, byte2 in zip(c1, c2):
            if byte1 == byte2:
                common_length += 1
            else:
                break
        
        # Omdat een blok-cipher per blok versleutelt, zal de overeenkomst
        # in één keer van 0 naar de volledige block size springen.
        if common_length > 0:
            return common_length
            
        i += 1

    return blocksize

#5c
# Eerst bepalen we de block size met de functie uit 5a
block_length = find_block_length()

# We maken een padding die precies 1 byte korter is dan de block size
# Let op de 'b' voor de string, zodat het bytes zijn en geen gewone tekst!
padding_length = block_length - 1
padding = b'A' * padding_length

# Nu sturen we deze padding naar de oracle om onze target ciphertext te krijgen
target_ciphertext = ECB_oracle(padding, key)

# We zijn specifiek geïnteresseerd in het eerste blok van deze target ciphertext
target_block = target_ciphertext[:block_length]

#5e
# We maken een lege variabele aan om de gevonden tekst in op te slaan (als bytes)
found_secret = b''

# We proberen alle mogelijke byte-waardes, van 0 tot en met 255
for i in range(256):
    # We maken een test-byte van het huidige getal 'i'
    test_byte = bytes([i])
    
    # Onze test-invoer is de padding (bijv. 15 keer 'A') + de test-byte
    test_plaintext = padding + test_byte
    
    # Stuur deze test-invoer naar de oracle
    test_ciphertext = ECB_oracle(test_plaintext, key)
    
    # Pak het eerste blok van deze nieuwe ciphertext
    test_block = test_ciphertext[:block_length]
    
    # Vergelijk het test-blok met ons doelwit-blok uit stap 5c
    if test_block == target_block:
        # Als ze exact hetzelfde zijn, hebben we de juiste letter geraden!
        found_secret += test_byte
        print(f"Hoera! De eerste byte is gevonden: {test_byte}")
        break # We hebben hem gevonden, dus we kunnen stoppen met zoeken


def find_secret_text():
    # 1. Bepaal de block size (gebruikt je functie uit 5a)
    block_length = find_block_length()
    
    # 2. Achterhaal hoe lang de geheime tekst ongeveer is
    # Dit doen we door een lege tekst te versleutelen en de lengte te meten
    empty_encryption = ECB_oracle(b'', key)
    total_length = len(empty_encryption)
    
    found_secret = b''
    
    print("Starten met kraken. Dit kan even duren...")
    
    # 3. Loop over elke positie van de geheime tekst
    for i in range(total_length):
        
        # Maak de padding telkens één byte korter. 
        # Zodra we een nieuw blok bereiken, begint de padding weer groot.
        pad_len = (block_length - 1) - (i % block_length)
        padding = b'A' * pad_len
        
        # Bepaal welk blok we als doelwit hebben (bij i=0 is dat het 1e blok, 
        # maar zodra i de block_length passeert, kijken we naar het 2e blok, etc.)
        block_start = (i // block_length) * block_length
        block_end = block_start + block_length
        
        # Vraag de doelwit-ciphertext op en selecteer het juiste blok
        target_ciphertext = ECB_oracle(padding, key)
        target_block = target_ciphertext[block_start:block_end]
        
        # Brute-force de byte voor deze positie
        for j in range(256):
            test_byte = bytes([j])
            
            # De test-invoer: padding + ALLES wat we al gevonden hebben + de test-byte
            test_plaintext = padding + found_secret + test_byte
            
            test_ciphertext = ECB_oracle(test_plaintext, key)
            test_block = test_ciphertext[block_start:block_end]
            
            # Als de blokken overeenkomen, hebben we de juiste letter te pakken!
            if test_block == target_block:
                found_secret += test_byte
                # We printen het tussentijdse resultaat zodat je hem live ziet groeien
                print(f"Gevonden tot nu toe: {found_secret.decode('ascii', errors='ignore')}")
                break # Stop met zoeken voor deze positie en ga door naar de volgende (i)
                
    return found_secret

# --- Start het script ---
# We roepen de functie aan en printen het eindresultaat netjes op het scherm
volledige_tekst = find_secret_text()

print("\n\n--- KRAKEN SUCCESVOL! DE GEHEIME TEKST IS: ---")
print(volledige_tekst.decode('ascii', errors='ignore'))