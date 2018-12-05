/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>

#include "common.h"
#include "norcow.h"
#include "storage.h"
#include "pbkdf2.h"
#include "rand.h"
#include "memzero.h"
#include "chacha20poly1305/rfc7539.h"

#define LOW_MASK 0x55555555

// Norcow storage key of the PIN entry log and PIN success log.
#define PIN_LOGS_KEY 0x0001

// Norcow storage key of the combined salt, EDEK and PIN verification code entry.
#define EDEK_PVC_KEY 0x0002

// Norcow storage key of the PIN set flag.
#define PIN_NOT_SET_KEY 0x0003

// The PIN value corresponding to an empty PIN.
#define PIN_EMPTY 1

// Maximum number of failed unlock attempts.
#define PIN_MAX_TRIES 15

// The total number of iterations to use in PBKDF2.
#define PIN_ITER_COUNT 20000

// If the top bit of APP is set, then the value is not encrypted.
#define FLAG_PUBLIC 0x80

// The length of the PIN entry log or the PIN success log in words.
#define PIN_LOG_WORDS 16

// The length of a word in bytes.
#define WORD_SIZE sizeof(uint32_t)

// The length of the data encryption key in bytes.
#define DEK_SIZE 32

// The length of the random salt in bytes.
#define PIN_SALT_SIZE 4

// The length of the PIN verification code in bytes.
#define PVC_SIZE 8

// The length of the Poly1305 MAC in bytes.
#define POLY1305_MAC_SIZE 16

// The length of the ChaCha20 IV (aka nonce) in bytes as per RFC 7539.
#define CHACHA20_IV_SIZE 12

// The length of the ChaCha20 block in bytes.
#define CHACHA20_BLOCK_SIZE 64

static secbool initialized = secfalse;
static secbool unlocked = secfalse;
static PIN_UI_WAIT_CALLBACK ui_callback = NULL;
static uint8_t cached_dek[DEK_SIZE];
static const uint8_t TRUE_BYTE = 1;
static const uint8_t FALSE_BYTE = 0;

static void handle_fault();

static void derive_kek(uint32_t pin, const uint8_t *salt, uint8_t kek[SHA256_DIGEST_LENGTH], uint8_t keiv[SHA256_DIGEST_LENGTH])
{
#if BYTE_ORDER == BIG_ENDIAN
    REVERSE32(pin, pin);
#endif

    // TODO Add more salt

    PBKDF2_HMAC_SHA256_CTX ctx;
    pbkdf2_hmac_sha256_Init(&ctx, (const uint8_t*) &pin, sizeof(pin), salt, PIN_SALT_SIZE, 1);
    pbkdf2_hmac_sha256_Update(&ctx, PIN_ITER_COUNT/2);
    pbkdf2_hmac_sha256_Final(&ctx, kek);
    pbkdf2_hmac_sha256_Init(&ctx, (const uint8_t*) &pin, sizeof(pin), salt, PIN_SALT_SIZE, 2);
    pbkdf2_hmac_sha256_Update(&ctx, PIN_ITER_COUNT/2);
    pbkdf2_hmac_sha256_Final(&ctx, keiv);
    memzero(&ctx, sizeof(PBKDF2_HMAC_SHA256_CTX));
    memzero(&pin, sizeof(pin));
}

static secbool set_pin(uint32_t pin)
{
    uint8_t buffer[PIN_SALT_SIZE + DEK_SIZE + POLY1305_MAC_SIZE];
    uint8_t *salt = buffer;
    uint8_t *edek = buffer + PIN_SALT_SIZE;
    uint8_t *pvc = buffer + PIN_SALT_SIZE + DEK_SIZE;

    uint8_t kek[SHA256_DIGEST_LENGTH];
    uint8_t keiv[SHA256_DIGEST_LENGTH];
    chacha20poly1305_ctx ctx;
    random_buffer(salt, PIN_SALT_SIZE);
    derive_kek(pin, salt, kek, keiv);
    rfc7539_init(&ctx, kek, keiv);
    memzero(kek, sizeof(kek));
    memzero(keiv, sizeof(keiv));
    chacha20poly1305_encrypt(&ctx, cached_dek, edek, DEK_SIZE);
    rfc7539_finish(&ctx, 0, DEK_SIZE, pvc);
    memzero(&ctx, sizeof(ctx));
    secbool ret = norcow_set(EDEK_PVC_KEY, buffer, PIN_SALT_SIZE + DEK_SIZE + PVC_SIZE);
    memzero(buffer, sizeof(buffer));

    if (ret == sectrue)
    {
        if (pin == PIN_EMPTY) {
            norcow_set(PIN_NOT_SET_KEY, &TRUE_BYTE, 1);
        } else {
            norcow_set(PIN_NOT_SET_KEY, &FALSE_BYTE, 0);
        }
    }

    memzero(&pin, sizeof(pin));
    return ret;
}

static secbool expand_guard_key(const uint32_t guard_key, uint32_t *guard_mask, uint32_t *guard)
{
    // TODO Add guard_key integrity check. Call handle_fault() on failure.
    *guard_mask = ((guard_key & LOW_MASK) << 1) | ((~guard_key) & LOW_MASK);
    *guard = (((guard_key & LOW_MASK) << 1) & guard_key) | (((~guard_key) & LOW_MASK) & (guard_key >> 1));
    return sectrue;
}

static secbool pin_logs_init()
{
    // The format of the PIN_LOGS_KEY entry is:
    // guard_key (1 word), pin_success_log (PIN_LOG_WORDS), pin_entry_log (PIN_LOG_WORDS)
    uint32_t logs[1 + 2*PIN_LOG_WORDS];

    // TODO Generate guard key so that it satisfies the integrity check.
    random_buffer((uint8_t*)logs, sizeof(uint32_t));

    uint32_t guard_mask;
    uint32_t guard;
    if (sectrue != expand_guard_key(logs[0], &guard_mask, &guard)) {
        return secfalse;
    }

    uint32_t unused = guard | ~guard_mask;
    for (size_t i = 1; i < 1 + 2*PIN_LOG_WORDS; ++i) {
        logs[i] = unused;
    }

    return norcow_set(PIN_LOGS_KEY, logs, sizeof(logs));
}

void storage_init(PIN_UI_WAIT_CALLBACK callback)
{
    initialized = secfalse;
    unlocked = secfalse;
    norcow_init();
    initialized = sectrue;
    ui_callback = callback;

    // If there is no EDEK, then generate a random DEK and store it.
    const void *val;
    uint16_t len;
    if (secfalse == norcow_get(EDEK_PVC_KEY, &val, &len)) {
        random_buffer(cached_dek, DEK_SIZE);
        set_pin(PIN_EMPTY);
        pin_logs_init();
    }
    storage_lock();
}

static secbool pin_fails_reset()
{
    const void *logs = NULL;
    uint16_t len = 0;

    if (sectrue != norcow_get(PIN_LOGS_KEY, &logs, &len) || len != WORD_SIZE*(1 + 2*PIN_LOG_WORDS)) {
        return secfalse;
    }

    uint32_t guard_mask;
    uint32_t guard;
    if (sectrue != expand_guard_key(*(const uint32_t*)logs, &guard_mask, &guard)) {
        return secfalse;
    }

    uint32_t unused = guard | ~guard_mask;
    const uint32_t *success_log = ((const uint32_t*)logs) + 1;
    const uint32_t *entry_log = success_log + PIN_LOG_WORDS;
    for (size_t i = 0; i < PIN_LOG_WORDS; ++i) {
        if (entry_log[i] == unused) {
            return sectrue;
        }
        if (success_log[i] != guard) {
            if (sectrue != norcow_update_word(PIN_LOGS_KEY, sizeof(uint32_t)*(i + 1), entry_log[i])) {
                return secfalse;
            }
        }
    }
    return pin_logs_init();
}

static secbool pin_fails_increase()
{
    const void *logs = NULL;
    uint16_t len = 0;

    if (sectrue != norcow_get(PIN_LOGS_KEY, &logs, &len) || len != WORD_SIZE*(1 + 2*PIN_LOG_WORDS)) {
        handle_fault();
        return secfalse;
    }

    uint32_t guard_mask;
    uint32_t guard;
    if (sectrue != expand_guard_key(*(const uint32_t*)logs, &guard_mask, &guard)) {
        handle_fault();
        return secfalse;
    }

    const uint32_t *entry_log = ((const uint32_t*)logs) + 1 + PIN_LOG_WORDS;
    for (size_t i = 0; i < PIN_LOG_WORDS; ++i) {
        if ((entry_log[i] & guard_mask) != guard) {
            handle_fault();
            return secfalse;
        }
        if (entry_log[i] != guard) {
            uint32_t word = entry_log[i] & ~guard_mask;
            word = ((word >> 1) | word) & LOW_MASK;
            word = (word >> 2) | (word >> 1);

            if (sectrue != norcow_update_word(PIN_LOGS_KEY, sizeof(uint32_t)*(i + 1 + PIN_LOG_WORDS), (word & ~guard_mask) | guard)) {
                handle_fault();
                return secfalse;
            }
            return sectrue;
        }

    }
    handle_fault();
    return secfalse;
}

static secbool pin_get_fails(uint32_t *ctr)
{
    *ctr = 255;

    const void *logs = NULL;
    uint16_t len = 0;
    if (sectrue != norcow_get(PIN_LOGS_KEY, &logs, &len) || len != WORD_SIZE*(1 + 2*PIN_LOG_WORDS)) {
        handle_fault();
        return secfalse;
    }

    uint32_t guard_mask;
    uint32_t guard;
    if (sectrue != expand_guard_key(*(const uint32_t*)logs, &guard_mask, &guard)) {
        handle_fault();
        return secfalse;
    }
    uint32_t unused = guard | ~guard_mask;

    const uint32_t *success_log = ((const uint32_t*)logs) + 1;
    const uint32_t *entry_log = success_log + PIN_LOG_WORDS;
    int current = -1;
    size_t i;
    for (i = 0; i < PIN_LOG_WORDS; ++i) {
        if ((entry_log[i] & guard_mask) != guard || (success_log[i] & guard_mask) != guard || (entry_log[i] & success_log[i]) != entry_log[i]) {
            handle_fault();
            return secfalse;
        }

        if (current == -1) {
            if (entry_log[i] != guard) {
                current = i;
            }
        } else {
            if (entry_log[i] != unused) {
                handle_fault();
                return secfalse;
            }
        }
    }

    if (current < 0 || current >= PIN_LOG_WORDS || i != PIN_LOG_WORDS) {
        handle_fault();
        return secfalse;
    }

    // Strip the guard bits from the current entry word and duplicate each data bit.
    uint32_t word = entry_log[current] & ~guard_mask;
    word = ((word >> 1) | word ) & LOW_MASK;
    word = word | (word << 1);
    // Verify that the entry word has form 0*1*.
    if ((word & (word + 1)) != 0) {
        handle_fault();
        return secfalse;
    }

    if (current == 0) {
        ++current;
    }

    // Count the number of set bits in the two current words of the success log.
    uint32_t fails = success_log[current-1] ^ entry_log[current-1];
    fails = fails - ((fails >> 1) & LOW_MASK);
    uint32_t fails2 = success_log[current] ^ entry_log[current];
    fails2 = fails2 - ((fails2 >> 1) & LOW_MASK);
    fails = (fails & 0x33333333) + ((fails >> 2) & 0x33333333) + (fails2 & 0x33333333) + ((fails2 >> 2) & 0x33333333);
    fails = (fails & 0x0F0F0F0F) + ((fails >> 4) & 0x0F0F0F0F);
    fails = fails + (fails >> 8);
    *ctr = (fails + (fails >> 16)) & 0xFF;
    return sectrue;
}

static secbool pin_cmp(uint32_t pin)
{
    const void *buffer = NULL;
    uint16_t len = 0;
    if (sectrue != norcow_get(EDEK_PVC_KEY, &buffer, &len) || len != PIN_SALT_SIZE + DEK_SIZE + PVC_SIZE) {
        memzero(&pin, sizeof(pin));
        return secfalse;
    }

    const uint8_t *salt = buffer;
    const uint8_t *edek = buffer + PIN_SALT_SIZE;
    const uint8_t *pvc = buffer + PIN_SALT_SIZE + DEK_SIZE;
    uint8_t kek[SHA256_DIGEST_LENGTH];
    uint8_t keiv[SHA256_DIGEST_LENGTH];
    uint8_t mac[POLY1305_MAC_SIZE];
    chacha20poly1305_ctx ctx;

    derive_kek(pin, salt, kek, keiv);
    memzero(&pin, sizeof(pin));
    rfc7539_init(&ctx, kek, keiv);
    memzero(kek, sizeof(kek));
    memzero(keiv, sizeof(keiv));
    chacha20poly1305_decrypt(&ctx, edek, cached_dek, DEK_SIZE);
    rfc7539_finish(&ctx, 0, DEK_SIZE, mac);
    memzero(&ctx, sizeof(ctx));
    unlocked = memcmp(mac, pvc, PVC_SIZE) == 0 ? sectrue : secfalse;
    memzero(mac, sizeof(mac));

    return unlocked;
}

secbool storage_check_pin(uint32_t pin)
{
    // Get the pin failure counter
    uint32_t ctr;
    if (sectrue != pin_get_fails(&ctr)) {
        memzero(&pin, sizeof(pin));
        return secfalse;
    }

    // Wipe storage if too many failures
    if (ctr > PIN_MAX_TRIES) {
        norcow_wipe();
        ensure(secfalse, "pin_fails_check_max");
    }

    // Sleep for 2^(ctr-1) seconds before checking the PIN.
    uint32_t wait = (1 << ctr) >> 1;
    uint32_t progress;
    for (uint32_t rem = wait; rem > 0; rem--) {
        for (int i = 0; i < 10; i++) {
            if (ui_callback) {
                if (wait > 1000000) {  // precise enough
                    progress = (wait - rem) / (wait / 1000);
                } else {
                    progress = ((wait - rem) * 10 + i) * 100 / wait;
                }
                ui_callback(rem, progress);
            }
            hal_delay(100);
        }
    }
    // Show last frame if we were waiting
    if ((wait > 0) && ui_callback) {
        ui_callback(0, 1000);
    }

    // First, we increase PIN fail counter in storage, even before checking the
    // PIN.  If the PIN is correct, we reset the counter afterwards.  If not, we
    // check if this is the last allowed attempt.
    if (sectrue != pin_fails_increase()) {
        memzero(&pin, sizeof(pin));
        return secfalse;
    }

    // Check that the PIN fail counter was incremented.
    uint32_t ctr_ck;
    if (sectrue != pin_get_fails(&ctr_ck) || ctr + 1 != ctr_ck) {
        handle_fault();
        return secfalse;
    }

    if (sectrue != pin_cmp(pin)) {
        // Wipe storage if too many failures
        if (ctr >= PIN_MAX_TRIES) {
            norcow_wipe();
            ensure(secfalse, "pin_fails_check_max");
        }
        return secfalse;
    }
    memzero(&pin, sizeof(pin));
    // Finally set the counter to 0 to indicate success.
    return pin_fails_reset();
}

secbool storage_lock() {
    memzero(cached_dek, DEK_SIZE);
    unlocked = secfalse;
    return sectrue;
}

secbool storage_unlock(uint32_t pin)
{
    storage_lock();
    if (sectrue == initialized && sectrue == storage_check_pin(pin)) {
        unlocked = sectrue;
    }
    memzero(&pin, sizeof(pin));
    return unlocked;
}

/*
 * Finds the data stored under key and writes its length to len. If val_dest is not NULL and max_len >= len, then the data is copied to val_dest.
 */
secbool storage_get(const uint16_t key, void *val_dest, const uint16_t max_len, uint16_t *len)
{
    const uint8_t app = key >> 8;
    // APP == 0 is reserved for PIN related values
    if (sectrue != initialized || app == 0) {
        return secfalse;
    }

    // If the top bit of APP is set, then the value is not encrypted and can be read from an unlocked device.
    const void *val_stored = NULL;
    if ((app & FLAG_PUBLIC) != 0) {
        if (sectrue != norcow_get(key, &val_stored, len)) {
            return secfalse;
        }
        if (val_dest == NULL) {
            return sectrue;
        }
        if (*len > max_len) {
            return secfalse;
        }
        memcpy(val_dest, val_stored, *len);
        return sectrue;
    }

    if (sectrue != unlocked) {
        return secfalse;
    }
    if (sectrue != norcow_get(key, &val_stored, len) || *len < CHACHA20_IV_SIZE + POLY1305_MAC_SIZE) {
        return secfalse;
    }
    *len -= CHACHA20_IV_SIZE + POLY1305_MAC_SIZE;
    if (val_dest == NULL) {
        return sectrue;
    }
    if (*len > max_len) {
        return secfalse;
    }

    const uint8_t *iv = val_stored;
    const uint8_t *ciphertext = val_stored + CHACHA20_IV_SIZE;
    const uint8_t *mac_stored = val_stored + CHACHA20_IV_SIZE + *len;
    uint8_t mac_computed[POLY1305_MAC_SIZE];
    chacha20poly1305_ctx ctx;
    rfc7539_init(&ctx, cached_dek, iv);
    chacha20poly1305_decrypt(&ctx, ciphertext, (uint8_t*) val_dest, *len);
    rfc7539_finish(&ctx, 0, *len, mac_computed);
    memzero(&ctx, sizeof(ctx));
    secbool ret = memcmp(mac_computed, mac_stored, POLY1305_MAC_SIZE) == 0 ? sectrue : secfalse;
    memzero(mac_computed, sizeof(mac_computed));
    return ret;
}

secbool storage_set(const uint16_t key, const void *val, const uint16_t len)
{
    const uint8_t app = key >> 8;
    // APP == 0 is reserved for PIN related values
    if (sectrue != initialized || sectrue != unlocked || app == 0) {
        return secfalse;
    }
    if ((app & FLAG_PUBLIC) != 0) {
        return norcow_set(key, val, len);
    }

    // The data will need to be encrypted, so preallocate space on the flash storage.
    uint16_t offset = 0;
    if (sectrue != norcow_set(key, NULL, CHACHA20_IV_SIZE + len + POLY1305_MAC_SIZE)) {
        return secfalse;
    }

    // Write the IV to the flash.
    uint8_t buffer[CHACHA20_BLOCK_SIZE + POLY1305_MAC_SIZE];
    random_buffer(buffer, CHACHA20_IV_SIZE);
    if (sectrue != norcow_update_bytes(key, offset, buffer, CHACHA20_IV_SIZE)) {
        return secfalse;
    }
    offset += CHACHA20_IV_SIZE;

    // Encrypt all blocks except for the last one.
    chacha20poly1305_ctx ctx;
    rfc7539_init(&ctx, cached_dek, buffer);
    size_t i;
    for (i = 0; i + CHACHA20_BLOCK_SIZE < len; i += CHACHA20_BLOCK_SIZE, offset += CHACHA20_BLOCK_SIZE) {
        chacha20poly1305_encrypt(&ctx, ((const uint8_t*) val) + i, buffer, CHACHA20_BLOCK_SIZE);
        if (sectrue != norcow_update_bytes(key, offset, buffer, CHACHA20_BLOCK_SIZE)) {
            memzero(&ctx, sizeof(ctx));
            memzero(buffer, sizeof(buffer));
            return secfalse;
        }
    }

    // Encrypt final block and compute message authentication tag.
    chacha20poly1305_encrypt(&ctx, ((const uint8_t*) val) + i, buffer, len - i);
    rfc7539_finish(&ctx, 0, len, buffer + len - i);
    secbool ret = norcow_update_bytes(key, offset, buffer, len - i + POLY1305_MAC_SIZE);
    memzero(&ctx, sizeof(ctx));
    memzero(buffer, sizeof(buffer));
    return ret;
}

secbool storage_has_pin(void)
{
    if (sectrue != initialized) {
        return secfalse;
    }

    const void *val = NULL;
    uint16_t len;
    if (sectrue != norcow_get(PIN_NOT_SET_KEY, &val, &len) || (len > 0 && *(uint8_t*)val != FALSE_BYTE)) {
        return secfalse;
    }
    return sectrue;
}

secbool storage_change_pin(uint32_t oldpin, uint32_t newpin)
{
    if (sectrue != initialized || sectrue != unlocked) {
        return secfalse;
    }
    if (sectrue != storage_check_pin(oldpin)) {
        return secfalse;
    }
    secbool ret = set_pin(newpin);
    memzero(&oldpin, sizeof(oldpin));
    memzero(&newpin, sizeof(newpin));
    return ret;
}

void storage_wipe(void)
{
    norcow_wipe();
}

static void handle_fault()
{
    static secbool in_progress = secfalse;

    // If fault handling is already in progress, then we are probably facing a fault injection attack, so wipe.
    if (secfalse != in_progress) {
        norcow_wipe();
        for(;;);
    }

    // We use the PIN fail counter as a fault counter. Increment the counter, check that it was incremented and halt.
    in_progress = sectrue;
    uint32_t ctr;
    if (sectrue != pin_get_fails(&ctr)) {
        norcow_wipe();
        for(;;);
    }

    if (sectrue != pin_fails_increase()) {
        norcow_wipe();
        for(;;);
    }

    uint32_t ctr_new;
    if (sectrue != pin_get_fails(&ctr_new) || ctr + 1 != ctr_new) {
        norcow_wipe();
    }
    for(;;);
}
