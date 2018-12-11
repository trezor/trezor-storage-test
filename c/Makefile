CC = gcc
CFLAGS = -Wall -fPIC -DTREZOR_STORAGE_TEST
LIBS =
INC = -I ../vendor/trezor-crypto
OBJ = storage.o norcow.o flash.o
OBJ += ../vendor/trezor-crypto/pbkdf2.o
OBJ += ../vendor/trezor-crypto/rand.o
OBJ += ../vendor/trezor-crypto/chacha20poly1305/rfc7539.o
OBJ += ../vendor/trezor-crypto/chacha20poly1305/chacha20poly1305.o
OBJ += ../vendor/trezor-crypto/chacha20poly1305/poly1305-donna.o
OBJ += ../vendor/trezor-crypto/chacha20poly1305/chacha_merged.o
OBJ += ../vendor/trezor-crypto/hmac.o
OBJ += ../vendor/trezor-crypto/sha2.o
OBJ += ../vendor/trezor-crypto/memzero.o
OUT = libtrezor-storage.so

$(OUT): $(OBJ)
	$(CC) $(CFLAGS) $(LIBS) $(OBJ) -shared -o $(OUT)

%.o: %.c %.h
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

clean:
	rm -f $(OUT) $(OBJ)
