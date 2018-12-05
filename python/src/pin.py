from . import consts


def derive_guard_mask_and_value(guard_key: bytes) -> (int, int):
    guard_key = int.from_bytes(guard_key, "little")

    if guard_key > 0xFFFFFFFF:
        raise ValueError("Invalid guard key")

    guard_mask = ((guard_key & consts.LOW_MASK) << 1) | (
        (~guard_key & 0xFFFFFFFF) & consts.LOW_MASK
    )
    guard = (((guard_key & consts.LOW_MASK) << 1) & guard_key) | (
        ((~guard_key & 0xFFFFFFFF) & consts.LOW_MASK) & (guard_key >> 1)
    )

    return guard_mask, guard


def get_init_logs(guard_key: bytes) -> bytes:
    guard_mask, guard = derive_guard_mask_and_value(guard_key)

    pin_success_log = 0
    pin_entry_log = 0
    for i in range(consts.PIN_LOG_SUCCESS_AND_ENTRY_SIZE // 4):
        pin_success_log = pin_success_log << 4 * 8
        pin_success_log = pin_success_log | ((~guard_mask & 0xFFFFFFFF) | guard)
        pin_entry_log = pin_entry_log << 4 * 8
        pin_entry_log = pin_entry_log | ((~guard_mask & 0xFFFFFFFF) | guard)

    return (
        guard_key
        + pin_success_log.to_bytes(consts.PIN_LOG_SUCCESS_AND_ENTRY_SIZE, "little")
        + pin_entry_log.to_bytes(consts.PIN_LOG_SUCCESS_AND_ENTRY_SIZE, "little")
    )
