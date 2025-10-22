#ifndef LT_HMAC_H
#define LT_HMAC_H

#include <stdint.h>
#include <stddef.h>

void lt_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t data_len,
                    uint8_t *out);

#endif
