"""Proof of concept searchable encrypted database.

Based on the final scheme described in [Song2000]_.

.. [Song2000] Song, Dawn Xiaoding, David Wagner, and Adrian Perrig. "Practical
   techniques for searches on encrypted data." In *Security and Privacy*, 2000.
   S&P 2000.  Proceedings. 2000 IEEE Symposium on, pp. 44-55. IEEE, 2000.

"""
import abc

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import modes, algorithms

class Client:
    """Client to access an ServerInterface."""

    KEY_NAMES = ('seed', 'hash', 'encrypt', 'index')

    def __init__(self, server, password, backend=None):
        """Create a client associated with a server interface.

        Parameters:

        server
          a ServerInterface connected to the database server

        password
          byte string client password used to generate keys

        backend
          (optional) a custom CryptoBackend to use

        """
        self.server = server
        self.password = password
        self.backend = backend or CryptoBackend()

        self.keys = self.backend.generate_keys(password)

    def store_document(document):
        """Store a document on the server.

        Parameters:

        document
          a list of byte strings

        """

class ServerInterface(metaclass=abc.ABCMeta):
    """Interface for an EDB server."""

    @abc.abstractmethod
    def search():
        """Search for an entry."""

class ServerInterface(ServerInterface):
    """Toy in-process in-memory server."""

class CryptoBackend:
    """Default CryptoBackend based on the cryptography package."""

    def generate_keys(self, password):
        """Return a dict of keys derived from the given password.

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
        return {
            key_name: self.hmac(password, key_name)
            for key_name in self.KEY_NAMES
        }


    @staticmethod
    def hmac(key, message):
        """Create a 256-bit HMAC of a message using key.

        Parameters:

        key
          byte string represeting HMAC key

        message
          byte string of data to hash

        """
        hmac_ = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        hmac_.update(message)
        return hmac_.finalize()
