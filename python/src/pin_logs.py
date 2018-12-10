import sys

from . import consts


def derive_guard_mask_and_value(guard_key: bytes) -> (int, int):
    guard_key = int.from_bytes(guard_key, sys.byteorder)

    if guard_key > 0xFFFFFFFF:
        raise ValueError("Invalid guard key")

    guard_mask = ((guard_key & consts.LOW_MASK) << 1) | (
        (~guard_key & 0xFFFFFFFF) & consts.LOW_MASK
    )
    guard = (((guard_key & consts.LOW_MASK) << 1) & guard_key) | (
        ((~guard_key & 0xFFFFFFFF) & consts.LOW_MASK) & (guard_key >> 1)
    )

    return _expand_to_log_size(guard_mask), _expand_to_log_size(guard)


def _expand_to_log_size(value: int) -> int:
    result = 0
    for i in range(0, consts.PIN_LOG_SIZE, 4):
        result = result | (value << i * 8)
    return result


def get_init_logs(guard_key: bytes) -> bytes:
    guard_mask, guard = derive_guard_mask_and_value(guard_key)

    pin_success_log = (~guard_mask & consts.ALL_FF_LOG) | guard
    pin_entry_log = (~guard_mask & consts.ALL_FF_LOG) | guard

    return (
        guard_key
        + to_bytes_by_words(pin_success_log)
        + to_bytes_by_words(pin_entry_log)
    )


def write_attempt_to_log(
    guard_mask: bytes, guard: bytes, pin_entry_log: bytes
) -> bytes:
    pin_entry_log = to_int_by_words(pin_entry_log)

    assert (pin_entry_log & guard_mask) == guard

    clean_pin_entry_log = remove_guard_bits(guard_mask, pin_entry_log)
    clean_pin_entry_log = clean_pin_entry_log >> 2  # set 11 to 00
    pin_entry_log = (clean_pin_entry_log & (~guard_mask & consts.ALL_FF_LOG)) | guard

    return to_bytes_by_words(pin_entry_log)


def remove_guard_bits(guard_mask: int, log: int) -> int:
    """
    Removes all guard bits and replaces each guard bit
    with its neighbour value.
    Example: 0g0gg1 -> 000011
    """
    log = log & (~guard_mask & consts.ALL_FF_LOG)
    log = ((log >> 1) | log) & _expand_to_log_size(consts.LOW_MASK)
    log = log | (log << 1)
    return log


def to_int_by_words(array: bytes) -> int:
    """
    Converts array of bytes into an int by reading word size
    of bytes then converted to int using the system's endianness.
    """
    assert len(array) % consts.WORD_SIZE == 0
    n = 0
    for i in range(0, len(array), consts.WORD_SIZE):
        n = (n << (consts.WORD_SIZE * 8)) + int.from_bytes(
            array[i : i + consts.WORD_SIZE], sys.byteorder
        )
    return n


def to_bytes_by_words(n: int) -> bytes:
    """
    Converting int back to bytes by words.
    """
    mask = (1 << (consts.WORD_SIZE * 8)) - 1
    array = bytes()
    for i in reversed(range(0, consts.PIN_LOG_SIZE, consts.WORD_SIZE)):
        array = array + ((n >> (i * 8)) & mask).to_bytes(
            consts.WORD_SIZE, sys.byteorder
        )
    return array
