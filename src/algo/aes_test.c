#include <dpi/debug.h>
#include "aes.h"
#include <openssl/evp.h>

int dtype;
int main(int argc, char *argv[])
{
  block rkey;
  aes_key_t key;
  int len, clen;
  const __m128i *sched;
  uint8_t akey[16];
  uint8_t in[16] = "Hello, world!!!!";
  uint8_t out[16];

  EVP_CIPHER_CTX *ctx;

  dtype = DPI_DEBUG_CIRCUIT;
  rkey = random_block();
  _mm_store_si128((__m128i *)akey, rkey);
  clen = 0;

  iprint(DPI_DEBUG_CIRCUIT, "Key", akey, 0, 16, 16);
  aes_128_set_encrypt_key(&rkey, &key);
  aes_encrypt(in, out, &key);

  iprint(DPI_DEBUG_CIRCUIT, "In (mm)", in, 0, 16, 16);
  iprint(DPI_DEBUG_CIRCUIT, "Out (mm)", out, 0, 16, 16);

  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, akey, NULL);
  EVP_EncryptUpdate(ctx, out, &len, in, 16);
  clen += len;

  iprint(DPI_DEBUG_CIRCUIT, "Out (evp)", out, 0, clen, 16);

  EVP_CIPHER_CTX_free(ctx);
  return 0;
}
