#pragma once
#include <stdint.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

typedef struct
{
  uint32_t state[16];
  uint32_t keystream[16];
  size_t available; // remaining keystream is available
} chacha20_ctx;

void chacha20_setup(chacha20_ctx *ctx, const uint8_t *key, uint32_t length, uint8_t nonce[8]);
void chacha20_set_counter(chacha20_ctx *ctx, uint64_t counter);
void chacha20_block(chacha20_ctx *ctx, uint32_t output[16]);
void chacha20_encrypt_bytes(chacha20_ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t length);
void chacha20_decrypt_bytes(chacha20_ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t length);
