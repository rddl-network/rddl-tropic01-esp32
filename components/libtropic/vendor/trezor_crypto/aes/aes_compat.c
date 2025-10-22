#include "aes.h"
#include "aes_compat.h"

// --- Fehlende Funktionsprototypen explizit deklarieren ---
AES_RETURN aes_encrypt_key128(const unsigned char *key, aes_encrypt_ctx cx[1]);
AES_RETURN aes_encrypt_key192(const unsigned char *key, aes_encrypt_ctx cx[1]);
AES_RETURN aes_encrypt_key256(const unsigned char *key, aes_encrypt_ctx cx[1]);
// ----------------------------------------------------------


// Kompatibilitäts-Wrapper für alte Trezor-Crypto-Implementierungen
int aes_encrypt_key(const unsigned char *key, int key_len, aes_encrypt_ctx cx[1])
{
    if (key_len == 16) {
        return aes_encrypt_key128(key, cx);
    } else if (key_len == 24) {
        return aes_encrypt_key192(key, cx);
    } else if (key_len == 32) {
        return aes_encrypt_key256(key, cx);
    } else {
        return -1; // ungültige Schlüssellänge
    }
}

AES_RETURN aes_encrypt_key128(const unsigned char *key, aes_encrypt_ctx cx[1]) {
    return aes_encrypt_key(key, 16, cx);
}

AES_RETURN aes_encrypt_key192(const unsigned char *key, aes_encrypt_ctx cx[1]) {
    return aes_encrypt_key(key, 24, cx);
}

AES_RETURN aes_encrypt_key256(const unsigned char *key, aes_encrypt_ctx cx[1]) {
    return aes_encrypt_key(key, 32, cx);
}
