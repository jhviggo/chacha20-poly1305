#include <string.h>
#include "chacha20.h"

// Little endian u8 to u32 conversion
#define U8TO32_LITTLE(p) (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))
// Little endian u32 to u8 conversion
#define U32TO8_LITTLE(b, i) (b)[0] = i & 0xFF; (b)[1] = (i >> 8) & 0xFF; (b)[2] = (i >> 16) & 0xFF; (b)[3] = (i >> 24) & 0xFF;
// Rotate left
#define ROTL32(v, n) ((v) << (n)) | ((v) >> (32 - (n)))
#define QUARTERROUND(x, a, b, c, d) \
  x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 16); \
  x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 12); \
  x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 8); \
  x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 7);
#define COUNTER 0

/**
 * @brief Sets the counter for the specific Chacha context
 * 
 * @param ctx the Chacha20 context
 * @param counterthe  counter value
 */
void chacha20_set_counter(chacha20_ctx *ctx, uint64_t counter) {
  ctx->state[12] = counter & UINT32_C(0xFFFFFFFF);
  ctx->state[13] = counter >> 32;
  ctx->available = 0;
}

/**
 * @brief Sets up the inital chacha context state, including the constant, key, counter and none
 * 
 * @param ctx the Chacha20 context
 * @param key the encryption key
 * @param length the length of the key
 * @param nonce the nonce
 */
void chacha20_setup(chacha20_ctx *ctx, const uint8_t *key, uint32_t length, uint8_t nonce[8]) {
  const char *constants = (length == 32 ? "expand 32-byte k" : "expand 16-byte k");
  ctx->state[0]  = U8TO32_LITTLE(constants + 0);
  ctx->state[1]  = U8TO32_LITTLE(constants + 4);
  ctx->state[2]  = U8TO32_LITTLE(constants + 8);
  ctx->state[3]  = U8TO32_LITTLE(constants + 12);
  ctx->state[4]  = U8TO32_LITTLE(key + 0 * 4);
  ctx->state[5]  = U8TO32_LITTLE(key + 1 * 4);
  ctx->state[6]  = U8TO32_LITTLE(key + 2 * 4);
  ctx->state[7]  = U8TO32_LITTLE(key + 3 * 4);
  ctx->state[8]  = U8TO32_LITTLE(key + 4 * 4);
  ctx->state[9]  = U8TO32_LITTLE(key + 5 * 4);
  ctx->state[10] = U8TO32_LITTLE(key + 6 * 4);
  ctx->state[11] = U8TO32_LITTLE(key + 7 * 4);
  ctx->state[12] = COUNTER;
  ctx->state[13] = COUNTER;
  ctx->state[14] = U8TO32_LITTLE(nonce + 0);
  ctx->state[15] = U8TO32_LITTLE(nonce + 4);
  ctx->available = 0;
}

/**
 * @brief Generates the block by running 20 rounds
 * 
 * @param ctx the Chacha20 context
 * @param output a little endian uint_8 array
 */
void chacha20_block(chacha20_ctx *ctx, uint32_t output[16]) {
  uint32_t *const nonce = ctx->state+12; //12 is where the 128 bit counter is
  memcpy(output, ctx->state, sizeof(ctx->state));

  // 10 rounds each of column and diagonal rounds 
  int i = 10;
  while (i > 0) {
    QUARTERROUND(output, 0, 4,  8, 12);
    QUARTERROUND(output, 1, 5,  9, 13);
    QUARTERROUND(output, 2, 6, 10, 14);
    QUARTERROUND(output, 3, 7, 11, 15);
    QUARTERROUND(output, 0, 5, 10, 15);
    QUARTERROUND(output, 1, 6, 11, 12);
    QUARTERROUND(output, 2, 7,  8, 13);
    QUARTERROUND(output, 3, 4,  9, 14);
    i--;
  }

  // Update the result
  for (int i = 0; i < 16; ++i) {
    uint32_t result = output[i] + ctx->state[i];
    U32TO8_LITTLE((uint8_t *)(output+i), result);
  }

  if (!++nonce[0] && !++nonce[1] && !++nonce[2]) {
    ++nonce[3];
  }
}

/**
 * @brief XOR the message with the key stream.
 * out = in ⊕ keystream
 * 
 * @param keystream the keystream generated in the block
 * @param in the message to be XOR'ed
 * @param out the output variable
 * @param length the length of the message
 */
static inline void chacha20_xor(uint8_t *keystream, const uint8_t **in, uint8_t **out, size_t length) {
  uint8_t *end_keystream = keystream + length;
  do {
    *(*out)++ = *(*in)++ ^ *keystream++;
  } while (keystream < end_keystream);
}

/**
 * @brief Chacha20 encrypt a plain text message by generating keystream and XOR'ing the stream and plain text message
 * 
 * @param ctx the Chacha20 context
 * @param in the plain text message to be encrypted
 * @param out the output variable
 * @param length the length of the message
 */

void chacha20_encrypt_bytes(chacha20_ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t length) {
  if (!length) {
    return;
  }
  uint8_t *const k = (uint8_t *)ctx->keystream;

  // If remaining keystream is available, use it
  if (ctx->available) {
    uint32_t amount = MIN(length, ctx->available);
    chacha20_xor(k + (sizeof(ctx->keystream) - ctx->available), &in, &out, amount);
    ctx->available -= amount;
    length -= amount;
  }

  // XOR remaining message if any
  while (length) {
    uint32_t amount = MIN(length, sizeof(ctx->keystream));
    // Update keystream with block
    chacha20_block(ctx, ctx->keystream);
    chacha20_xor(k, &in, &out, amount);
    length -= amount;
    ctx->available = sizeof(ctx->keystream) - amount;
  }
}

/**
 * @brief Chacha20 decrypt a plain text message by generating keystream and XOR'ing the stream and plain text message.
 * The encryption calls the encryption function directly, as they are equivalent
 * 
 * @param ctx the Chacha20 context
 * @param in the plain text message to be encrypted
 * @param out the output variable
 * @param length the length of the message
 */
void chacha20_decrypt_bytes(chacha20_ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t length) {
  chacha20_encrypt_bytes(ctx, in, out, length);
}
