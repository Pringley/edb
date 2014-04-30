"""EDB client."""
import base64

from edb import crypto
from edb.constants import BLOCK_BYTES, MATCH_BYTES, LEFT_BYTES
from edb.errors import EDBError

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

    def __init__(self, passphrase):
        """Create a client.

        Parameters:

        passphrase
          byte string client passphrase used to generate keys

        """
        self.passphrase = passphrase

        self.keys = crypto.generate_keys(passphrase, self.KEY_NAMES)
        self.connected = False

    def encrypt(self, word):
        """Encrypt a word."""
        salt = crypto.get_random_bytes(BLOCK_BYTES)
        preword = self.preprocess(word)
        return base64.encodebytes(salt + self.stream_encrypt(salt, preword))

    def decrypt(self, b64ctxt):
        """Decrypt ciphertext from a given index."""
        try:
            salted_ctxt = base64.decodebytes(b64ctxt)
        except:
            raise EDBError("invalid base64")
        if len(salted_ctxt) != 2 * BLOCK_BYTES:
            raise EDBError("invalid ciphertext -- incorrect length")
        salt, ciphertext = salted_ctxt[:BLOCK_BYTES], salted_ctxt[BLOCK_BYTES:]
        preword = self.stream_decrypt(salt, ciphertext)
        return self.postprocess(preword)

    def query(self, word):
        """Return the search parameters (preword, word_key) for word."""
        preword = self.preprocess(word)
        left_part = self.left_part(preword)
        word_key = self.word_key(left_part)
        return base64.encodebytes(preword + word_key)

    def stream_encrypt(self, salt, preword):
        """Encrypt a (preprocessed) word with given salt."""
        left_part = self.left_part(preword)
        word_key = self.word_key(left_part)
        stream_prefix = self.stream_prefix(salt)
        stream_suffix = self.stream_suffix(word_key, stream_prefix)
        return crypto.xor(preword, stream_prefix + stream_suffix)

    def stream_decrypt(self, salt, ciphertext):
        """Decrypt ciphertext with given salt, return (preprocessed) word."""
        left_ciphertext = self.left_part(ciphertext)
        stream_prefix = self.stream_prefix(salt)
        left_part = crypto.xor(left_ciphertext, stream_prefix)
        word_key = self.word_key(left_part)
        stream_suffix = self.stream_suffix(word_key, stream_prefix)
        return crypto.xor(ciphertext, stream_prefix + stream_suffix)

    def stream_prefix(self, salt):
        """Return the stream prefix for the given salt."""
        return crypto.prfunction(self.keys['seed'],
                                salt,
                                length=(LEFT_BYTES))

    def block_encrypt(self, plaintext):
        """Return the deterministically preencrypted word."""
        return crypto.encrypt(self.keys['encrypt'], plaintext)

    def block_decrypt(self, ciphertext):
        """Return the decrypted block."""
        return crypto.decrypt(self.keys['encrypt'], ciphertext)

    def word_key(self, left_part):
        """Return the word-specific key given its left_part."""
        return crypto.prfunction(self.keys['hash'], left_part)

    def stream_suffix(self, word_key, stream_prefix):
        """Return the last bytes of the stream cipher."""
        return crypto.prfunction(word_key, stream_prefix, MATCH_BYTES)

    def preprocess(self, word):
        """Pad and preencrypt a raw word."""
        padded_word = crypto.pad(word)
        return self.block_encrypt(padded_word)

    def postprocess(self, preword):
        """Postdecrypt and unpad a (preproccessed) word."""
        padded_word = self.block_decrypt(preword)
        return crypto.unpad(padded_word)

    def left_part(self, block):
        """Return the left_part of a block."""
        return block[:(LEFT_BYTES)]
