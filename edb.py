"""Proof of concept searchable encrypted database.

Based on the final scheme described in [Song2000]_.

Tested under Python 3.3.2 on OS X 10.9, using pycrypto 2.6.1.

.. [Song2000] Song, Dawn Xiaoding, David Wagner, and Adrian Perrig. "Practical
   techniques for searches on encrypted data." In *Security and Privacy*, 2000.
   S&P 2000.  Proceedings. 2000 IEEE Symposium on, pp. 44-55. IEEE, 2000.

"""
import base64

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol import KDF
from Crypto.Util import Counter

BLOCK_BYTES = 32 # 256 bits
MATCH_BYTES = 4  # only last 32 bits of message are checked during search

def test():
    """Run basic test cases."""
    passphrase = b"hunter2 is not a good password"
    backend = CryptoBackend()
    client = Client(passphrase)

    def p64(string):
        """Print bytes in base64."""
        print(base64.b64encode(string))

    # Make sure keys are generated properly.
    for name in client.KEY_NAMES:
        key = client.keys[name]
        assert isinstance(key, bytes)
        assert len(key) == BLOCK_BYTES

    # Test encrypt/decrypt.
    message = b"7" * BLOCK_BYTES
    c = backend.encrypt(client.keys['encrypt'], message)
    assert backend.decrypt(client.keys['encrypt'], c) == message

    # Test pseudorandom generator.
    for i in range(10):
        block = backend.prg(client.keys['seed'], i)
        assert isinstance(block, bytes)
        assert len(block) == BLOCK_BYTES

    # Test xor function.
    test_block = b"t"  * BLOCK_BYTES
    null_block = b"\0" * BLOCK_BYTES
    assert backend.xor(null_block, test_block) == test_block
    assert backend.xor(test_block, test_block) == null_block

class Client:
    """Client to access an EDB.

    The keys dict will contain byte strings:

    seed
      the 256-bit random seed used to initialize the random number
      generator

    hash
      the 256-bit key used to generate entry keys

    encrypt
      the 256-bit key used to pre-encrypt words before entry into the
      database

    index
      the 256-bit key used to generate index keys

    """

    KEY_NAMES = ('seed', 'hash', 'encrypt', 'index')

    def __init__(self, passphrase, backend=None):
        """Create a client.

        Parameters:

        passphrase
          byte string client passphrase used to generate keys

        backend
          (optional) a custom CryptoBackend to use

        """
        self.passphrase = passphrase
        self.backend = backend or CryptoBackend()

        self.keys = self.backend.generate_keys(passphrase, self.KEY_NAMES)
        self.connected = False

    def store_document(self, document):
        """Store a document on the server.

        Parameters:

        document
          a list of byte strings

        """

class CryptoBackend:
    """Default CryptoBackend based on the cryptography package."""

    def generate_keys(self, passphrase, names):
        """Return a dict of keys derived from the given passphrase.

        For each name in names, generate one key.

        (Note that no salt is used, so the generation is deterministic. The
        passphrase **must** be very strong.)

        """
        key_material = KDF.PBKDF2(
            passphrase, b"",
            dkLen=BLOCK_BYTES*len(names),
            count=10000,
            prf=self.prf,
        )
        keys = {
            name: key_material[index:index+BLOCK_BYTES]
            for index, name in enumerate(names)
        }
        return keys

    @staticmethod
    def prg(key, index, length=BLOCK_BYTES, message=None):
        """Pseudorandom generator.

        Return a pseudorandom 256-bit block.

        key
          byte string represeting HMAC key

        index
          integer representing counter index

        length
          (optional) number of bytes to output, default 32 or len(message)

        message
          (optional) byte string to be XOR'd with the input

        """
        if message is None:
            message = b'\0' * length
        counter = Counter.new(AES.block_size * 8, initial_value=index)
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)
        return cipher.encrypt(message)

    @staticmethod
    def prf(key, message):
        """Pseudorandom function.

        Create a 256-bit HMAC of a message using key.

        Parameters:

        key
          byte string represeting HMAC key

        message
          byte string of data to hash

        """
        return HMAC.HMAC(key, message, SHA256).digest()

    def encrypt(self, key, message):
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

    def decrypt(self, key, ciphertext):
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

    @staticmethod
    def pad(message):
        """Pad message to exactly 256 bits using PKCS#7 variant."""
        if len(message) >= BLOCK_BYTES:
            raise TypeError("message must be less than 256 bits")
        padlen = BLOCK_BYTES - len(message)
        return message + bytes([padlen]) * padlen

    @staticmethod
    def unpad(message):
        """Unpad message."""
        if len(message) != BLOCK_BYTES:
            raise TypeError("expected 256-bit padded message")
        padlen = message[-1]
        return message[:-padlen]

    @staticmethod
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

if __name__ == '__main__':
    test()
