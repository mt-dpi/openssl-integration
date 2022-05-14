#include <openssl/evp.h>
#include <stdio.h>
#include <time.h>

void baseline_encryption(EVP_CIPHER_CTX *ectx, unsigned char *tval, int tlen);
void fixedkey_encryption(EVP_CIPHER_CTX *ectx, unsigned char *key, unsigned char *tval, int tlen);
void nonfixedkey_encryption(EVP_CIPHER_CTX *ectx, unsigned char *tval, int tlen);

int main(int argc, char *argv[])
{
  int i, tlen, elen;
  EVP_CIPHER_CTX *ectx;
  const EVP_CIPHER *eevp;
  clock_t start, end;
  unsigned char key[16] = {
    0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa,
    0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa,
  };

  unsigned char tval[16] = {
    0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
    0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
  };

  unsigned char eval[16] = {0, };

  tlen = sizeof(tval);
  eevp = EVP_aes_128_ecb();
  ectx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ectx, eevp, NULL, key, NULL);

  start = clock();
  for (i=0; i<50000000; i++)
  {
    baseline_encryption(ectx, tval, tlen);
  }
  end = clock();
  printf("baseline encryption for %d times: %.8lf us\n", i, (end * 1.0 - start)/CLOCKS_PER_SEC * 1000000);

  start = clock();
  for (i=0; i<50000000; i++)
  {
    EVP_EncryptUpdate(ectx, eval, &elen, tval, tlen);
  }
  end = clock();
  printf("baseline encryption for %d times: %.8lf us\n", i, (end * 1.0 - start)/CLOCKS_PER_SEC * 1000000);

  start = clock();
  for (i=0; i<50000000; i++)
  {
    nonfixedkey_encryption(ectx, tval, tlen);
  }
  end = clock();
  printf("non fixed key encryption for %d times: %.8lf us\n", i, (end * 1.0 - start)/CLOCKS_PER_SEC * 1000000);

  start = clock();
  for (i=0; i<50000000; i++)
  {
    fixedkey_encryption(ectx, key, tval, tlen);
  }
  end = clock();
  printf("fixed key encryption for %d times: %.8lf us\n", i, (end * 1.0 - start)/CLOCKS_PER_SEC * 1000000);

}

void baseline_encryption(EVP_CIPHER_CTX *ectx, unsigned char *tval, int tlen)
{
  unsigned char eval[16] = {0, };
  int elen;

  EVP_EncryptUpdate(ectx, eval, &elen, tval, tlen);
}

void fixedkey_encryption(EVP_CIPHER_CTX *ectx, unsigned char *key, unsigned char *tval, int tlen)
{
  int i, rc, elen, hlen, bsize;
  unsigned char eval[16] = {0, };
  unsigned char hval[16] = {0, };
  unsigned char tmp[16] = {0, };
  unsigned char sbuf[8] = {0, 0, 0, 0, 0, 0, 0, 1};
  bsize = 16;

  for (i=0; i<bsize; i++)
    tmp[i] = tval[i] ^ key[i];
  rc = EVP_EncryptUpdate(ectx, hval, &hlen, tmp, bsize);

  for (i=0; i<bsize; i++)
    hval[i] = hval[i] ^ tmp[i];

  for (i=0; i<bsize; i++)
    tmp[i] = hval[i] ^ sbuf[i];

  rc = EVP_EncryptUpdate(ectx, eval, &elen, tmp, bsize);

  for (i=0; i<bsize; i++)
    eval[i] = eval[i] ^ tmp[i];
}

void nonfixedkey_encryption(EVP_CIPHER_CTX *ectx, unsigned char *tval, int tlen)
{
  int rc, hlen, elen, bsize;
  unsigned char eval[16] = {0, };
  unsigned char hval[16] = {0, };
  unsigned char sbuf[8] = {0, 0, 0, 0, 0, 0, 0, 1};
  EVP_CIPHER_CTX *etctx;
  bsize = 16;

  rc = EVP_EncryptUpdate(ectx, hval, &hlen, tval, tlen);
  etctx = EVP_CIPHER_CTX_new();
  rc = EVP_EncryptInit_ex(etctx, EVP_aes_128_ecb(), NULL, hval, NULL);
  rc = EVP_EncryptUpdate(etctx, eval, &elen, sbuf, bsize);
  EVP_CIPHER_CTX_free(etctx);
}
