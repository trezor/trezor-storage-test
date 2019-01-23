from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import consts


def derive_kek_keiv(salt: bytes, pin: int) -> (bytes, bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=consts.KEK_SIZE + consts.KEIV_SIZE,
        salt=bytes(salt),
        iterations=10000,
        backend=default_backend(),
    )
    pbkdf_output = kdf.derive(pin.to_bytes(4, "little"))
    # the first 256b is Key Encryption Key
    kek = pbkdf_output[: consts.KEK_SIZE]
    # following with 96b of Initialization Vector
    keiv = pbkdf_output[consts.KEK_SIZE :]

    return kek, keiv


def chacha_poly_encrypt(
    key: bytes, iv: bytes, data: bytes, additional_data: bytes = None
) -> (bytes, bytes):
    chacha = ChaCha20Poly1305(key)
    chacha_output = chacha.encrypt(iv, bytes(data), additional_data)
    # cipher text and 128b authentication tag
    return chacha_output[: len(data)], chacha_output[len(data) :]


def chacha_poly_decrypt(
    key: bytes, app_key: int, iv: bytes, data: bytes, additional_data: bytes = None
) -> bytes:
    chacha = ChaCha20Poly1305(key)
    chacha_output = chacha.decrypt(bytes(iv), bytes(data), additional_data)
    return chacha_output


def validate_pin(pin: int, salt: bytes, edek: bytes, pvc: bytes):
    """
    This a little bit hackish. We do not store the whole
    authentication tag so we can't decrypt using ChaCha20Poly1305
    because it obviously checks the tag first and fails.
    So we are using the sole ChaCha20 cipher to decipher and then encrypt
    again with Chacha20Poly1305 to get the tag and compare it to PVC.
    """
    kek, keiv = derive_kek_keiv(salt, pin)

    algorithm = algorithms.ChaCha20(kek, (1).to_bytes(4, "little") + keiv)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    dek = decryptor.update(bytes(edek))

    _, tag = chacha_poly_encrypt(kek, keiv, dek)
    return tag[: consts.PVC_SIZE] == pvc


def calculate_hmacs(sak, keys) -> bytes:
    """
    This calculates HMAC-SHA-256(SAK, (XOR_i) HMAC-SHA-256(SAK, KEY_i)).
    In other words, it does HMAC for every KEY and XORs it all together.
    One more final HMAC is then performed on the result.
    """
    hmacs = _hmac(sak, keys[0])
    for key in keys[1:]:
        hmacs = _xor(hmacs, _hmac(sak, key))
    return _hmac(sak, hmacs)[: consts.SAT_SIZE]


def init_hmacs(sak: bytes) -> bytes:
    return _hmac(sak, b"\x00" * hashes.SHA256.digest_size)[: consts.SAT_SIZE]


def _hmac(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()


def _xor(first: bytes, second: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(first, second))
