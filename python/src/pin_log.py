import sys

from . import consts, helpers, prng


class PinLog:
    def __init__(self, norcow):
        self.norcow = norcow

    def init(self):
        guard_key = prng.random_buffer(consts.PIN_LOG_GUARD_KEY_SIZE)
        guard_mask, guard = self.derive_guard_mask_and_value(guard_key)

        pin_success_log = (~guard_mask & consts.ALL_FF_LOG) | guard
        pin_entry_log = (~guard_mask & consts.ALL_FF_LOG) | guard

        data = (
            guard_key
            + helpers.to_bytes_by_words(pin_success_log)
            + helpers.to_bytes_by_words(pin_entry_log)
        )
        self.norcow.set(consts.PIN_LOG_KEY, data)

    def derive_guard_mask_and_value(self, guard_key: bytes) -> (int, int):
        guard_key = int.from_bytes(guard_key, sys.byteorder)
        if guard_key > 0xFFFFFFFF:
            raise ValueError("Invalid guard key")

        guard_mask = ((guard_key & consts.LOW_MASK) << 1) | (
            (~guard_key & 0xFFFFFFFF) & consts.LOW_MASK
        )
        guard = (((guard_key & consts.LOW_MASK) << 1) & guard_key) | (
            ((~guard_key & 0xFFFFFFFF) & consts.LOW_MASK) & (guard_key >> 1)
        )
        return helpers.expand_to_log_size(guard_mask), helpers.expand_to_log_size(guard)

    def write_attempt(self):
        guard_key, pin_success_log, pin_entry_log = self._get_logs()
        guard_mask, guard = self.derive_guard_mask_and_value(guard_key)
        assert (pin_entry_log & guard_mask) == guard

        clean_pin_entry_log = self.remove_guard_bits(guard_mask, pin_entry_log)
        clean_pin_entry_log = clean_pin_entry_log >> 2  # set 11 to 00
        pin_entry_log = (
            clean_pin_entry_log & (~guard_mask & consts.ALL_FF_LOG)
        ) | guard

        self._write(guard_key, pin_success_log, pin_entry_log)

    def write_success(self):
        guard_key, pin_success_log, pin_entry_log = self._get_logs()
        pin_success_log = pin_entry_log

        self._write(guard_key, pin_success_log, pin_entry_log)

    def get_failures_count(self) -> int:
        guard_key, pin_succes_log, pin_entry_log = self._get_logs()
        guard_mask, _ = self.derive_guard_mask_and_value(guard_key)

        pin_succes_log = self.remove_guard_bits(guard_mask, pin_succes_log)
        pin_entry_log = self.remove_guard_bits(guard_mask, pin_entry_log)

        # divide by two because bits are doubled after remove_guard_bits()
        return bin(pin_succes_log - pin_entry_log).count("1") // 2

    def remove_guard_bits(self, guard_mask: int, log: int) -> int:
        """
        Removes all guard bits and replaces each guard bit
        with its neighbour value.
        Example: 0g0gg1 -> 000011
        """
        log = log & (~guard_mask & consts.ALL_FF_LOG)
        log = ((log >> 1) | log) & helpers.expand_to_log_size(consts.LOW_MASK)
        log = log | (log << 1)
        return log

    def _get_logs(self) -> (int, int, int):
        pin_log = self.norcow.get(consts.PIN_LOG_KEY)
        guard_key = pin_log[: consts.PIN_LOG_GUARD_KEY_SIZE]
        guard_mask, guard = self.derive_guard_mask_and_value(guard_key)
        pin_entry_log = pin_log[consts.PIN_LOG_GUARD_KEY_SIZE + consts.PIN_LOG_SIZE :]
        pin_entry_log = helpers.to_int_by_words(pin_entry_log)
        pin_success_log = pin_log[
            consts.PIN_LOG_GUARD_KEY_SIZE : consts.PIN_LOG_GUARD_KEY_SIZE
            + consts.PIN_LOG_SIZE
        ]
        pin_success_log = helpers.to_int_by_words(pin_success_log)

        return guard_key, pin_success_log, pin_entry_log

    def _write(self, guard_key: int, pin_success_log: int, pin_entry_log: int):
        pin_log = (
            guard_key
            + helpers.to_bytes_by_words(pin_success_log)
            + helpers.to_bytes_by_words(pin_entry_log)
        )
        self.norcow.replace(consts.PIN_LOG_KEY, pin_log)
