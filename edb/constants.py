"""Constants for the EDB."""

BLOCK_BYTES = 32 # 256 bits
MATCH_BYTES = 4  # only last 32 bits of message are checked during search
LEFT_BYTES = BLOCK_BYTES - MATCH_BYTES

PAILLIER_BITS = 512
