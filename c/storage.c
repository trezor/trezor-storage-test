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

// Byte-length of flash section containing fail counters.
#define PIN_FAIL_KEY 0x0001
#define PIN_FAIL_SECTOR_SIZE 32

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

// The length of the data encryption key in bytes.
#define DEK_SIZE 32

// The length of the random salt in bytes.
#define PIN_SALT_SIZE 4

// The length of the PIN verification code in bytes.
#define PVC_SIZE 8

// The length of the Poly1305 MAC in bytes.
#define POLY1305_MAC_SIZE 16

// The length of the ChaCha20 IV (aka nonce) in bytes as per RFC 7539.
#define CHACHA_IV_SIZE 12

static secbool initialized = secfalse;
static secbool unlocked = secfalse;
static PIN_UI_WAIT_CALLBACK ui_callback = NULL;
static uint8_t cached_dek[DEK_SIZE];
static const uint8_t TRUE_BYTE = 1;
static const uint8_t FALSE_BYTE = 0;

void derive_kek(uint32_t pin, const uint8_t *salt, uint8_t kek[SHA256_DIGEST_LENGTH], uint8_t keiv[SHA256_DIGEST_LENGTH])
{
    // TODO Add more salt

    PBKDF2_HMAC_SHA256_CTX ctx;
    pbkdf2_hmac_sha256_Init(&ctx, (const uint8_t*) &pin, sizeof(pin), salt, PIN_SALT_SIZE, 1);
    pbkdf2_hmac_sha256_Update(&ctx, PIN_ITER_COUNT/2);
    pbkdf2_hmac_sha256_Final(&ctx, kek);
    pbkdf2_hmac_sha256_Init(&ctx, (const uint8_t*) &pin, sizeof(pin), salt, PIN_SALT_SIZE, 2);
    pbkdf2_hmac_sha256_Update(&ctx, PIN_ITER_COUNT/2);
    pbkdf2_hmac_sha256_Final(&ctx, keiv);
    memzero(&ctx, sizeof(PBKDF2_HMAC_SHA256_CTX));
}

static secbool set_pin(const uint32_t pin)
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
    ctx.chacha20.input[12] = 0; // TODO Remove when the rfc7539_init() bug is fixed.
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

    return ret;
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
    }
}

static secbool pin_fails_reset(uint16_t ofs)
{
    return norcow_update(PIN_FAIL_KEY, ofs, 0);
}

static secbool pin_fails_increase(const uint32_t *ptr, uint16_t ofs)
{
    uint32_t ctr = *ptr;
    ctr = ctr << 1;

    if (sectrue != norcow_update(PIN_FAIL_KEY, ofs, ctr)) {
        return secfalse;
    }

    uint32_t check = *ptr;
    if (ctr != check) {
        return secfalse;
    }
    return sectrue;
}

static void pin_fails_check_max(uint32_t ctr)
{
    if (~ctr >= (1 << PIN_MAX_TRIES)) {
        norcow_wipe();
        ensure(secfalse, "pin_fails_check_max");
    }
}

static secbool pin_cmp(const uint32_t pin)
{
    const void *buffer = NULL;
    uint16_t len = 0;
    if (sectrue != norcow_get(EDEK_PVC_KEY, &buffer, &len) || len != PIN_SALT_SIZE + DEK_SIZE + PVC_SIZE) {
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
    ctx.chacha20.input[12] = 0; // TODO Remove when the rfc7539_init() bug is fixed.
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

static secbool pin_get_fails(const uint32_t **pinfail, uint32_t *pofs)
{
    const void *vpinfail;
    uint16_t pinfaillen;
    unsigned int ofs;
    // The PIN_FAIL_KEY points to an area of words, initialized to
    // 0xffffffff (meaning no pin failures).  The first non-zero word
    // in this area is the current pin failure counter.  If  PIN_FAIL_KEY
    // has no configuration or is empty, the pin failure counter is 0.
    // We rely on the fact that flash allows to clear bits and we clear one
    // bit to indicate pin failure.  On success, the word is set to 0,
    // indicating that the next word is the pin failure counter.

    // Find the current pin failure counter
    if (secfalse != norcow_get(PIN_FAIL_KEY, &vpinfail, &pinfaillen)) {
        *pinfail = vpinfail;
        for (ofs = 0; ofs < pinfaillen / sizeof(uint32_t); ofs++) {
            if (((const uint32_t *) vpinfail)[ofs]) {
                *pinfail = vpinfail;
                *pofs = ofs;
                return sectrue;
            }
        }
    }

    // No pin failure section, or all entries used -> create a new one.
    uint32_t pinarea[PIN_FAIL_SECTOR_SIZE];
    memset(pinarea, 0xff, sizeof(pinarea));
    if (sectrue != norcow_set(PIN_FAIL_KEY, pinarea, sizeof(pinarea))) {
        return secfalse;
    }
    if (sectrue != norcow_get(PIN_FAIL_KEY, &vpinfail, &pinfaillen)) {
        return secfalse;
    }
    *pinfail = vpinfail;
    *pofs = 0;
    return sectrue;
}

secbool storage_check_pin(const uint32_t pin)
{
    const uint32_t *pinfail = NULL;
    uint32_t ofs;
    uint32_t ctr;

    // Get the pin failure counter
    if (pin_get_fails(&pinfail, &ofs) != sectrue) {
        return secfalse;
    }

    // Read current failure counter
    ctr = pinfail[ofs];
    // Wipe storage if too many failures
    pin_fails_check_max(ctr);

    // Sleep for ~ctr seconds before checking the PIN.
    uint32_t progress;
    for (uint32_t wait = ~ctr; wait > 0; wait--) {
        for (int i = 0; i < 10; i++) {
            if (ui_callback) {
                if ((~ctr) > 1000000) {  // precise enough
                    progress = (~ctr - wait) / ((~ctr) / 1000);
                } else {
                    progress = ((~ctr - wait) * 10 + i) * 100 / (~ctr);
                }
                ui_callback(wait, progress);
            }
            hal_delay(100);
        }
    }
    // Show last frame if we were waiting
    if ((~ctr > 0) && ui_callback) {
        ui_callback(0, 1000);
    }

    // First, we increase PIN fail counter in storage, even before checking the
    // PIN.  If the PIN is correct, we reset the counter afterwards.  If not, we
    // check if this is the last allowed attempt.
    if (sectrue != pin_fails_increase(pinfail + ofs, ofs * sizeof(uint32_t))) {
        return secfalse;
    }
    if (sectrue != pin_cmp(pin)) {
        // Wipe storage if too many failures
        pin_fails_check_max(ctr << 1);
        return secfalse;
    }
    // Finally set the counter to 0 to indicate success.
    return pin_fails_reset(ofs * sizeof(uint32_t));
}

secbool storage_lock() {
    memzero(cached_dek, DEK_SIZE);
    unlocked = secfalse;
    return sectrue;
}

secbool storage_unlock(const uint32_t pin)
{
    storage_lock();
    if (sectrue == initialized && sectrue == storage_check_pin(pin)) {
        unlocked = sectrue;
    }
    return unlocked;
}

secbool storage_get_len(const uint16_t key, uint16_t *len)
{
    const void *val;
    const uint8_t app = key >> 8;
    // APP == 0 is reserved for PIN related values
    if (sectrue != initialized || app == 0) {
        return secfalse;
    }
    // If the top bit of APP is set, then the value is not encrypted and can be read from an unlocked device.
    if ((app & FLAG_PUBLIC) != 0) {
        return norcow_get(key, &val, len);
    }
    if (sectrue != unlocked){
        return secfalse;
    }
    // If the value is encrypted, then return the length of the plaintext.
    secbool ret = norcow_get(key, &val, len);
    if (*len < CHACHA_IV_SIZE + POLY1305_MAC_SIZE) {
        return secfalse;
    }
    *len -= CHACHA_IV_SIZE + POLY1305_MAC_SIZE;
    return ret;
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
    if (sectrue != norcow_get(key, &val_stored, len) || *len < CHACHA_IV_SIZE + POLY1305_MAC_SIZE) {
        return secfalse;
    }
    *len -= CHACHA_IV_SIZE + POLY1305_MAC_SIZE;
    if (val_dest == NULL) {
        return sectrue;
    }
    if (*len > max_len) {
        return secfalse;
    }

    const uint8_t *iv = val_stored;
    const uint8_t *ciphertext = val_stored + CHACHA_IV_SIZE;
    const uint8_t *mac_stored = val_stored + CHACHA_IV_SIZE + *len;
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

secbool storage_set(const uint16_t key, const void *val, uint16_t len)
{
    const uint8_t app = key >> 8;
    // APP == 0 is reserved for PIN related values
    if (sectrue != initialized || sectrue != unlocked || app == 0) {
        return secfalse;
    }
    if ((app & FLAG_PUBLIC) != 0) {
        return norcow_set(key, val, len);
    }

    size_t buffer_size = CHACHA_IV_SIZE + len + POLY1305_MAC_SIZE;
    uint8_t *buffer = (uint8_t*)malloc(buffer_size);
    if (buffer == NULL) {
        return secfalse;
    }
    uint8_t *iv = buffer;
    uint8_t *ciphertext = buffer + CHACHA_IV_SIZE;
    uint8_t *mac = buffer + CHACHA_IV_SIZE + len;

    chacha20poly1305_ctx ctx;
    random_buffer(iv, CHACHA_IV_SIZE);
    rfc7539_init(&ctx, cached_dek, iv);
    chacha20poly1305_encrypt(&ctx, (uint8_t*) val, ciphertext, len);
    rfc7539_finish(&ctx, 0, len, mac);
    memzero(&ctx, sizeof(ctx));

    secbool ret = norcow_set(key, buffer, buffer_size);
    memzero(buffer, buffer_size);
    free(buffer);
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

secbool storage_change_pin(const uint32_t oldpin, const uint32_t newpin)
{
    if (sectrue != initialized || sectrue != unlocked) {
        return secfalse;
    }
    if (sectrue != storage_check_pin(oldpin)) {
        return secfalse;
    }
    return set_pin(newpin);
}

void storage_wipe(void)
{
    norcow_wipe();
}
