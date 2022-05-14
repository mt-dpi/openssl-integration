#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/evp.h>

unsigned long get_current_time(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * 1000000 + tv.tv_usec;
}

int main(int argc, char *argv[])
{
  unsigned char msg1[16] = "aaaaaaaaaaaaaaaa";
  unsigned char msg2[16] = "bbbbbbbbbbbbbbbb";
  unsigned char msg3[16] = "cccccccccccccccc";
  unsigned char msg4[16] = "dddddddddddddddd";
  unsigned char out[16] = {0, };
  unsigned char key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};
  unsigned char iv[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};
  int i, rc, len, count;
  EVP_CIPHER_CTX *ctx;
  const EVP_CIPHER *evp;
  clock_t start, end;

  ctx = EVP_CIPHER_CTX_new();
  evp = EVP_aes_128_ecb();
  rc = EVP_EncryptInit_ex(ctx, evp, NULL, key, NULL);
  if (!rc)
    printf("rc after EVP_EncryptInit_ex(): %d\n", rc);
  EVP_CIPHER_CTX_set_padding(ctx, 1);
  start = clock();
  for (count=0; count<50000000; count++)
  {
    rc = EVP_EncryptUpdate(ctx, out, &len, msg1, 16);
    if (rc != 1)
    {
      EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv);
    }
  }
  end = clock();
  rc = EVP_EncryptFinal_ex(ctx, msg1, &len);

  printf("start: %lu, end: %lu\n", start, end);
  printf("count: %d\n", count);
  printf("%d encryption in %.8f s, %.2f encryption/us\n", count, (end * 1.0 - start)/CLOCKS_PER_SEC, count*1.0/(end-start));
  printf("averaged encryption time: %.8f us\n", (end*1.0 - start)/CLOCKS_PER_SEC/count * 1000000);
  return 0;
}
