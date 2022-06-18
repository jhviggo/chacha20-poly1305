# Chacha20-poly1305 Embedded project

By Viggo Petersen

University: VIA University College

Course: SCP

This is a C implementation of ChaCha20 and Poly1305 tested with ESP-IDF using an ESP32. Please visit https://cr.yp.to/chacha.html and https://cr.yp.to/mac.html for the original papers on the algorithms made by Daniel J. Bernstein.

## How to use the algorithms
### Chacha20
Below is a snippet of how to use the Chacha20 Algorithm.

```c
uint8_t text_key[32] = "12345678901234567890123456789012"; // some 32byte key
uint8_t text_plain[20] = "Some secret message";
uint8_t nonce[8] = "12345678"; // 8byte nonce
chacha20_ctx ctx;
uint32_t len = sizeof text_plain;
uint8_t *output = alloca(len);
memset(output, 0, len);

// setup state and encrypt
chacha20_setup(&ctx, text_key, sizeof(text_key), nonce);
chacha20_encrypt_bytes(&ctx, text_plain, output, len);
printf("%s\n", output);

// reset state and decrypt
chacha20_setup(&ctx, text_key, sizeof(text_key), nonce);
chacha20_decrypt_bytes(&ctx, output, output, len);
printf("%s\n", output);
...
```
### Poly1305
Below is a snippet of how to use the Poly1305 algorithm, please refer to `benchmark_poly` function in the `main.c` file for the full code, alternatively check out the `test_poly.c` file for a more extensive use and test example.
```c
void example_poly(char *text) {
  unsigned char key[32];
  unsigned char mac[16];
  unsigned char msg[1001];
  size_t i;
  poly1305_power_on_self_test();
  // set key to some data
  for (i = 0; i < sizeof(key); i++)
    key[i] = (unsigned char)(i + 221);

  // set msg to typecast text
  for (i = 0; i < sizeof(msg); i++)
    msg[i] = (unsigned char)text[i];

  poly1305_auth(mac, msg, sizeof(msg), key);
...
```

# Library functions

## Chacha20

### chacha20_setup()
void chacha20_setup(chacha20_ctx *ctx, const uint8_t *key, uint32_t length, uint8_t nonce[8])

#### Note
Sets up the initial state of the given Chacha20 context

#### Parameters
* **\*ctz** the Chacha20 context containing the state and keystream
* **\*key** the encryption/decryption key
* **length** the length of the key
* **nonce** the nonce used in the chacha state

-----

### chacha20_set_counter()
void chacha20_set_counter(chacha20_ctx *ctx, uint64_t counter);

#### Note
Sets the counter inside the state to a given value

#### Parameters
* **\*ctx** the Chacha20 context
* **counter** the counter value to set inside the state

-----

### chacha20_block()
void chacha20_block(chacha20_ctx *ctx, uint32_t output[16]);

#### Note
Generates the chacha block by running through the quarterrounds

#### Parameters
* **\*ctx** the Chacha20 context
* **output** the output array to write the new block to

-----

### chacha20_encrypt_bytes()
void chacha20_encrypt_bytes(chacha20_ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t length);

#### Note
Encrypt a given message using the given context

#### Parameters
* **\*ctx** the Chacha20 context
* **\*in** the input message to encrypt
* **\*out** the location to save the encrypted message to
* **length** the lenght of the message to encrypt

-----

### chacha20_decrypt_bytes()
void chacha20_decrypt_bytes(chacha20_ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t length);

#### Note
Decrypt a given message using the given context

#### Parameters
* **\*ctx** the Chacha20 context
* **\*in** the input message to encrypt
* **\*out** the location to save the encrypted message to
* **length** the lenght of the message to encrypt
-----

## Poly1305
Note that this Poly1305 implementation was done by [poly1305-donna](https://github.com/floodyberry/poly1305-donna) so please go support them if you like their project. Also go check out their documentation in their repository.

### poly1305_init()
void poly1305_init(poly1305_context *ctx, const unsigned char key[32]);

#### Note
Initialize the Poly1305 state

#### Parameters
* **\*ctx** the Poly1305 context
* **key** the key used to generate the MAC

-----

### poly1305_update()
void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes);

#### Note
Update a given amount of bytes of the block or the entire 16byte block

#### Parameters
* **\*ctx** the Poly1305 context
* **\*m** list of bytes to use for the update
* **bytes** the amount of bytes to update

-----

### poly1305_finish()
void poly1305_finish(poly1305_context *ctx, unsigned char mac[16]);

#### Note
Process the remaining block and finish calculating the MAC (Message Authentication Code)

#### Parameters
* **\*ctx** the Poly1305 context
* **mac** the output variable which will contain the finished MAC

-----

### poly1305_auth()
void poly1305_auth(unsigned char mac[16], const unsigned char *m, size_t bytes, const unsigned char key[32]);

#### Note
Creates an authenticator for a given message

#### Parameters
* **mac** the buffer which receives the 16byte authenticator
* **\*m** the message to authenticate
* **key** the key to use

-----

### poly1305_verify()
int poly1305_verify(const unsigned char mac1[16], const unsigned char mac2[16]);

#### Note
Verify the authentication of two MACs

#### Parameters
* **mac1** the first MAC to verify
* **mac2** the second MAC to verify

#### returns
Returns `1` if they are equal or `0` if they are not

-----

### poly1305_power_on_self_test()
int poly1305_power_on_self_test(void);

#### Note
Test the implementation to ensure the library is functional

#### returns
Returns `1` if all tests pass and library is functional else return `0`
