import base64

from edb import crypto
from edb.constants import BLOCK_BYTES, MATCH_BYTES, LEFT_BYTES

def match(b64field, b64query):
    """Return True if the given query matches the field.

    Parameters:

    b64field -- a concatenation of salt and ciphertext, each BLOCK_BYTES long,
                encoded in base64

    b64query -- a concatenation of preword and word_key, each BLOCK_BYTES long,
             encoded in base64

    """
    # Ensure byte strings.
    if isinstance(b64field, str):
        b64field = str.encode(b64field)
    elif not isinstance(b64field, (bytes, bytearray)):
        return False
    if isinstance(b64query, str):
        b64query = str.encode(b64query)
    elif not isinstance(b64query, (bytes, bytearray)):
        print('bad instance', type(b64query), b64query)
        return False

    # Decode from base64.
    try:
        field = base64.decodebytes(b64field)
        query = base64.decodebytes(b64query)
    except:
        return False

    # Require correct sizes.
    if len(query) != 2 * BLOCK_BYTES or len(field) != 2 * BLOCK_BYTES:
        return False

    # Check using Song et al.'s Final Scheme.
    preword, word_key = query[:BLOCK_BYTES], query[BLOCK_BYTES:]
    _, ciphertext = field[:BLOCK_BYTES], field[BLOCK_BYTES:]
    block = crypto.xor(ciphertext, preword)
    prefix, suffix = block[:LEFT_BYTES], block[LEFT_BYTES:]
    hashed_prefix = crypto.prfunction(word_key, prefix, length=MATCH_BYTES)
    return hashed_prefix == suffix
