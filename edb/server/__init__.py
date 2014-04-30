"""EDB server."""

from edb import crypto
from edb.constants import MATCH_BYTES, LEFT_BYTES

class Server:
    """EDB server."""

    def __init__(self, backend=None):
        """Initialize the server."""
        self.words = []

    def add_word(self, encrypted_word):
        """Add an encrypted word to the database."""
        self.words.append(encrypted_word)

    def search(self, preword, word_key):
        """Search for a word in the database.

        Returns a list of (index, ciphertext) pairs for potential matches.

        Parameters:

        preword
          The pre-encrypted padded word for which to search.

        word_key
          The word-specific key to the pseudorandom function.

        """
        return [(index, ciphertext)
                for index, ciphertext in enumerate(self.words)
                if self.match(ciphertext, preword, word_key)]

    def match(self, ciphertext, preword, word_key):
        """Return True if the ciphertext is preword encrypted with word_key."""
        block = crypto.xor(ciphertext, preword)
        prefix, suffix = block[:LEFT_BYTES], block[LEFT_BYTES:]
        hashed_prefix = crypto.prfunction(word_key, prefix, length=MATCH_BYTES)
        return hashed_prefix == suffix
