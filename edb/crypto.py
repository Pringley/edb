import base64
import json
import collections.abc

from Crypto import Random
from Crypto.Random import random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol import KDF
from Crypto.Util import Counter

from edb.constants import BLOCK_BYTES
from edb.errors import EDBError
from edb import paillier

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

def generate_keyinfo(keyschema):
    """Return a dict of secure randomly-generated keys.

    The provided parameter `keyschema` should be a dict mapping key names to
    descriptions. For example:

        {
            'encrypt': {'type': 'block', 'bits': 256},
            'hmac': {'type': 'block', 'bits': 256},
            'homomorphic': {'type': 'paillier', 'bits': 512}
        }

    Supported types include "block" (random string of bit size) and "paillier"
    (key for the paillier cryptosystem). The default type is "block" if
    unspecified. The default number of bits is 256.

    Example return value:

        {
            'encrypt': b'\xb5c\x1d...',
            'hmac': b'\x7f\xa7\xcd...',
            'homomorphic': paillier.Key(modulus=..., ...)
        }

    """
    keyinfo = {}
    for name, attrs in keyschema.items():
        bad_attrs = set(attrs.keys()) - set(['type', 'bits'])
        if bad_attrs:
            raise EDBError("invalid schema: unexpected attrs: "
                           "{}".format(bad_attrs))
        keytype = attrs.get('type', 'block')
        try:
            keybits = int(attrs.get('bits', 256))
        except ValueError:
            raise EDBError("invalid schema: {}/bits is not int".format(name))
        if keytype == 'block':
            key = get_random_bytes(keybits // 8)
        elif keytype == 'paillier':
            key = paillier.generate_keys(keybits)
        else:
            raise EDBError("invalid schema: bad type: ".format(keytype))
        keyinfo[name] = key
    return keyinfo

def write_keyinfo(keyinfo, filename):
    """Write keyinfo to file."""
    psz_keyinfo = preserialize_keyinfo(keyinfo)
    with open(filename, 'w') as wfile:
        json.dump(psz_keyinfo, wfile)

def read_keyinfo(filename):
    """Load keyinfo from file."""
    with open(filename) as rfile:
        psz_keyinfo = json.load(rfile)
    return postdeserialize_keyinfo(psz_keyinfo)

def preserialize_keyinfo(keyinfo):
    """Prepare keyinfo for JSON serialization."""
    psz_keyinfo = {}
    for name, keydata in keyinfo.items():
        if isinstance(keydata, str):
            sz_data = base64.encodebytes(str.encode(keydata)).decode()
        elif isinstance(keydata, (bytes, bytearray)):
            sz_data = base64.encodebytes(keydata).decode()
        elif isinstance(keydata, paillier.Key):
            sz_data = {'paillier': list(keydata)}
        elif isinstance(keydata, paillier.PublicKey):
            sz_data = {'paillier.pub': list(keydata)}
        else:
            raise EDBError("unexpected keydata")
        psz_keyinfo[name] = sz_data
    return psz_keyinfo

def postdeserialize_keyinfo(psz_keyinfo):
    """Undo the preprocessing done by preserialize_keyinfo."""
    keyinfo = {}
    for name, sz_data in psz_keyinfo.items():
        if isinstance(sz_data, str):
            sz_bytes = str.encode(sz_data)
            try:
                keydata = base64.decodebytes(sz_bytes)
            except:
                raise EDBError("serialized keydata not b64")
        elif isinstance(sz_data, (bytes, bytearray)):
            try:
                keydata = base64.decodebytes(sz_data)
            except:
                raise EDBError("serialized keydata not b64")
        elif isinstance(sz_data, dict) and 'paillier' in sz_data:
            sz_tuple = sz_data['paillier']
            if not (isinstance(sz_tuple, collections.abc.Iterable)
                    and len(sz_tuple) == 4):
                raise EDBError("invalid paillier keydata")
            keydata = paillier.Key._make(sz_tuple)
        elif isinstance(sz_data, dict) and 'paillier.pub' in sz_data:
            sz_tuple = sz_data['paillier.pub']
            if not (isinstance(sz_tuple, collections.abc.Iterable)
                    and len(sz_tuple) == 2):
                raise EDBError("invalid paillier keydata")
            keydata = paillier.PublicKey._make(sz_tuple)
        else:
            raise EDBError("invalid keydata")
        keyinfo[name] = keydata
    return keyinfo

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
