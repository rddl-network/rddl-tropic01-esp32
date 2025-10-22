#pragma once
#include "aes.h"

int aes_encrypt_key(const unsigned char *key, int key_len, aes_encrypt_ctx cx[1]);
