from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol import KDF
from Crypto.Util import Counter

from edb.constants import BLOCK_BYTES

def generate_keys(passphrase, names):
    """Return a dict of keys derived from the given passphrase.

    For each name in names, generate one key.

    (Note that no salt is used, so the generation is deterministic. The
    passphrase **must** be very strong.)

    """
    key_material = KDF.PBKDF2(
        passphrase, b"",
        dkLen=BLOCK_BYTES*len(names),
        count=10000,
        prf=prfunction,
    )
    keys = {
        name: key_material[index:index+BLOCK_BYTES]
        for index, name in enumerate(names)
    }
    return keys

def prgenerator(key, index, length=None, message=None):
    """Pseudorandom generator.

    Return a pseudorandom 256-bit block.

    key
      byte string represeting key

    index
      integer representing counter index

    length
      (optional) number of bytes to output, default 32 or len(message)

    message
      (optional) byte string to be XOR'd with the input

    """
    if message is None:
        message = b'\0' * (length or BLOCK_BYTES)
    counter = Counter.new(AES.block_size * 8, initial_value=index)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return cipher.encrypt(message)

def prfunction(key, message, length=None):
    """Pseudorandom function.

    Create a 256-bit HMAC of a message using key.

    Parameters:

    key
      byte string represeting key

    message
      byte string of data to hash

    length
      (optional) bytes to return, default 32

    """
    digest = HMAC.HMAC(key, message, SHA256).digest()
    if length is not None:
        return digest[:length]
    return digest

def encrypt(key, message):
    """Deterministic encryption function.

    Parameters:

    key
      byte string represeting encryption key

    message
      byte string of length 32 (exactly 256 bits)

    """
    if len(message) != BLOCK_BYTES:
        raise TypeError("expected 256-bit message")
    cipher = AES.new(key, AES.MODE_CBC, b"\0"*AES.block_size)
    return cipher.encrypt(message)

def decrypt(key, ciphertext):
    """Decryption function.

    Parameters:

    key
      byte string represeting decryption key

    ciphertext
      byte string of length 32 (exactly 256 bits)

    """
    if len(ciphertext) != BLOCK_BYTES:
        raise TypeError("expected 256-bit ciphertext")
    cipher = AES.new(key, AES.MODE_CBC, b"\0"*AES.block_size)
    return cipher.decrypt(ciphertext)

def get_random_bytes(amount):
    return Random.get_random_bytes(amount)

def pad(message):
    """Pad message to exactly 256 bits using PKCS#7 variant."""
    if len(message) >= BLOCK_BYTES:
        raise TypeError("message must be less than 256 bits")
    padlen = BLOCK_BYTES - len(message)
    return message + bytes([padlen]) * padlen

def unpad(message):
    """Unpad message."""
    if len(message) != BLOCK_BYTES:
        raise TypeError("expected 256-bit padded message")
    padlen = message[-1]
    return message[:-padlen]

def xor(original, *others):
    """Perform xor on one or more byte strings of equal length."""
    size = len(original)
    result = bytearray(original)
    for other in others:
        if len(other) != size:
            raise TypeError("mismatched lengths for xor")
        for index in range(size):
            result[index] ^= other[index]
    return bytes(result)
