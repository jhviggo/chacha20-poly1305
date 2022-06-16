#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_spi_flash.h"
#include "chacha20.h"
#include "poly1305-donna.h"
#include "test_chacha.h"
#include "test_poly.h"

/**
 * @brief Combined test of Chacha20 and Poly1305
 */
void test_chacha20_poly1305(const char *text_key, const char *text_nonce, const char *text_plain, uint64_t counter) {
  printf("Testing full chacha20-poly1305\n");

  // Chacha20 setup
  chacha20_ctx ctx;
  uint8_t chacha_key[32];
  uint8_t nonce[8];
  uint32_t len = strlen(text_plain) / 2;
  uint8_t *plain = alloca(len);
  uint8_t *output = alloca(len);
  hex2byte(text_key, chacha_key);
  hex2byte(text_nonce, nonce);
  hex2byte(text_plain, plain);
  chacha20_setup(&ctx, chacha_key, sizeof(chacha_key), nonce);

  //Exact length test
  memset(output, 0, len);
  chacha20_set_counter(&ctx, counter);
  chacha20_encrypt_bytes(&ctx, plain, output, len);

  // poly1305 setup
  // 0x43, 0xdd, 0xce, 0xb5, 0x2e, 0x73, 0x87, 0xe6, 0x2b, 0x72, 0x86, 0xe5, 0x2a, 0x71, 0x85, 0xe4
  const unsigned char expected[16] = { 0x43, 0xdd, 0xce, 0xb5, 0x2e, 0x73, 0x87, 0xe6, 0x2b, 0x72, 0x86, 0xe5, 0x2a, 0x71, 0x85, 0xe4 };
	unsigned char poly_key[32];
	unsigned char mac[16];
	size_t i;
	int success = poly1305_power_on_self_test();
  printf("poly1305 self test: %s\n", success ? "successful" : "failed");
  
  for (i = 0; i < sizeof(poly_key); i++)
		poly_key[i] = (unsigned char)(i + 221);
  poly1305_auth(mac, output, sizeof(output), poly_key);

  printf("sample mac is ");
	for (i = 0; i < sizeof(mac); i++)
		printf("%02x", mac[i]);
	printf(" (%s)\n", poly1305_verify(expected, mac) ? "correct" : "incorrect");
  printf("CHACHA20-POLY1305 test succeeded!\n");
}

/**
 * @brief Benchmark of Chacha20 algorithm
 */
void benchmark_chacha(const char *text_key, const char *text_nonce, const char *text_plain) {
  chacha20_ctx ctx;
  uint8_t chacha_key[32];
  uint8_t nonce[8];
  uint32_t len = strlen(text_plain) / 2;
  uint8_t *plain = alloca(len);
  uint8_t *output = alloca(len);
  hex2byte(text_key, chacha_key);
  hex2byte(text_nonce, nonce);
  hex2byte(text_plain, plain);
  chacha20_setup(&ctx, chacha_key, sizeof(chacha_key), nonce);
  memset(output, 0, len);
  // benchmark encryption
  printf("Starting chacha benchmark\n");
  for (int j = 0; j < 10; j++) {
    clock_t t = clock();
    for (int i = 0; i < 1000; i++) {
      chacha20_encrypt_bytes(&ctx, plain, output, len);
    }
    t = clock() - t;
    double time_spent = (double)t / CLOCKS_PER_SEC;
    printf("Took %fs\n", time_spent);
  }
}

/**
 * @brief Benchmark of Poly1305 algorithm
 */
void benchmark_poly(char *text) {
	unsigned char key[32];
	unsigned char mac[16];
  unsigned char msg[1001];
	size_t i;
	poly1305_power_on_self_test();
	for (i = 0; i < sizeof(key); i++)
		key[i] = (unsigned char)(i + 221);
  for (i = 0; i < sizeof(msg); i++)
		msg[i] = (unsigned char)text[i];

  // benchmark encryption
  printf("Starting poly benchmark\n");
  for (int j = 0; j < 10; j++) {
    clock_t t = clock();
    for (int i = 0; i < 1000; i++) {
      poly1305_auth(mac, msg, sizeof(msg), key);
    }
    t = clock() - t;
    double time_spent = (double)t / CLOCKS_PER_SEC;
    printf("Took %fs\n", time_spent);
  }
}

void app_main(void) {
  printf("Welcome!\n");
  srand(0);
  int l = 1000;
  char *str = malloc(l + 1);
  memset(str, 'A', l);
  test_chacha_run();
  test_poly1305();
  test_chacha20_poly1305("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 0);
  benchmark_chacha("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000", str);
  benchmark_poly(str);
  for (int i = 10; i >= 0; i--) {
    printf("Restarting in %d seconds...\n", i);
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }
  printf("Restarting now.\n");
  fflush(stdout);
  esp_restart();
}
