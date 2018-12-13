# App ID where PIN log is stored.
PIN_APP_ID = 0x00

# Norcow storage key of the PIN entry log and PIN success log.
PIN_LOG_KEY = (PIN_APP_ID << 8) | 0x01

# Length of word in bytes.
WORD_SIZE = 4

# Length of items in the PIN entry log
PIN_LOG_GUARD_KEY_SIZE = 4
# Length of both success log and entry log
PIN_LOG_SIZE = 64

# Used for in guard bits operations.
LOW_MASK = 0x55555555

# Log initialized to all FFs.
ALL_FF_LOG = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

# Norcow storage key of the combined salt, EDEK and PIN verification code entry.
EDEK_PVC_KEY = (PIN_APP_ID << 8) | 0x02

# Norcow storage key of the PIN set flag.
PIN_NOT_SET_KEY = (PIN_APP_ID << 8) | 0x03

# Boolean values are stored as a simple 0/1 int.
TRUE_BYTE = b"\x01"
FALSE_BYTE = b"\x00"

# The PIN value corresponding to an empty PIN.
PIN_EMPTY = 1

# Maximum number of failed unlock attempts.
PIN_MAX_TRIES = 15

# The total number of iterations to use in PBKDF2.
PIN_ITER_COUNT = 20000

# If the top bit of APP is set, then the value is not encrypted.
FLAG_PUBLIC = 0x80

# The length of the data encryption key in bytes.
DEK_SIZE = 32

# The length of the random salt in bytes.
PIN_SALT_SIZE = 4
PIN_HARDWARE_SALT_SIZE = 32

# The length of the PIN verification code in bytes.
PVC_SIZE = 8

# The length of the Poly1305 MAC in bytes.
POLY1305_MAC_SIZE = 16

# The length of the ChaCha20 IV (aka nonce) in bytes as per RFC 7539.
CHACHA_IV_SIZE = 12

# The length of KEK in bytes.
KEK_SIZE = 32

# The length of KEIV in bytes.
KEIV_SIZE = 12

# Signalizes free storage.
NORCOW_KEY_FREE = 0xFFFF
