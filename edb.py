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
        block = backend.prgenerator(client.keys['seed'], i)
        assert isinstance(block, bytes)
        assert len(block) == BLOCK_BYTES

    # Test xor function.
    test_block = b"t"  * BLOCK_BYTES
    null_block = b"\0" * BLOCK_BYTES
    assert backend.xor(null_block, test_block) == test_block
    assert backend.xor(test_block, test_block) == null_block

    # Test client encrypt/decrypt.
    index = 3
    word = b"test"
    ciphertext = client.encrypt_word(index, word)
    assert client.decrypt_word(index, ciphertext) == word

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

    def encrypt_word(self, index, word):
        """Encrypt a word (to put in the given index)."""
        preword = self.preprocess(word)
        return self.stream_encrypt(index, preword)

    def decrypt_word(self, index, ciphertext):
        """Decrypt ciphertext from a given index."""
        preword = self.stream_decrypt(index, ciphertext)
        return self.postprocess(preword)

    def stream_encrypt(self, index, preword):
        """Encrypt a (preprocessed) word at index."""
        left_part = self.left_part(preword)
        word_key = self.word_key(left_part)
        stream_prefix = self.stream_prefix(index)
        stream_suffix = self.stream_suffix(word_key, stream_prefix)
        return self.backend.xor(preword, stream_prefix + stream_suffix)

    def stream_decrypt(self, index, ciphertext):
        """Decrypt ciphertext at index, return (preprocessed) word."""
        left_ciphertext = self.left_part(ciphertext)
        stream_prefix = self.stream_prefix(index)
        left_part = self.backend.xor(left_ciphertext, stream_prefix)
        word_key = self.word_key(left_part)
        stream_suffix = self.stream_suffix(word_key, stream_prefix)
        return self.backend.xor(ciphertext, stream_prefix + stream_suffix)

    def stream_prefix(self, index):
        """Return the stream prefix for the word at index."""
        return self.backend.prgenerator(self.keys['seed'],
                                index,
                                length=(BLOCK_BYTES - MATCH_BYTES))

    def block_encrypt(self, plaintext):
        """Return the deterministically preencrypted word."""
        return self.backend.encrypt(self.keys['encrypt'], plaintext)

    def block_decrypt(self, ciphertext):
        """Return the decrypted block."""
        return self.backend.decrypt(self.keys['encrypt'], ciphertext)

    def word_key(self, left_part):
        """Return the word-specific key given its left_part."""
        return self.backend.prfunction(self.keys['hash'], left_part)

    def stream_suffix(self, word_key, stream_prefix):
        """Return the last bytes of the stream cipher."""
        return self.backend.prfunction(word_key, stream_prefix, MATCH_BYTES)

    def preprocess(self, word):
        """Pad and preencrypt a raw word."""
        padded_word = self.backend.pad(word)
        return self.block_encrypt(padded_word)

    def postprocess(self, preword):
        """Postdecrypt and unpad a (preproccessed) word."""
        padded_word = self.block_decrypt(preword)
        return self.backend.unpad(padded_word)

    def left_part(self, block):
        """Return the left_part of a block."""
        return block[:(BLOCK_BYTES - MATCH_BYTES)]

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
            prf=self.prfunction,
        )
        keys = {
            name: key_material[index:index+BLOCK_BYTES]
            for index, name in enumerate(names)
        }
        return keys

    @staticmethod
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

    @staticmethod
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
