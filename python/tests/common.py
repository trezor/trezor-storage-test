def all_ff_bytes(data: bytes):
    return all(i == 0xFF for i in data)


def mock_urandom_simple(length: int) -> bytes:
    return b"\x01" * length
