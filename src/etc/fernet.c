#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include "fernet.h"
#include "base64.h"
#include "pbytes.h"

#include <dpi/debug.h>
#include <dpi/defines.h>


fernet_t *init_fernet(uint8_t *key, int len)
{
  fstart("key: %p, len: %d", key, len);
  assert(key != NULL);
  assert(len > 0);

  fernet_t *ret;
  int rc, klen;
  uint8_t tmp[FERNET_KEY_BYTES] = {0, };
  uint8_t *p;
  
  ret = (fernet_t *)calloc(1, sizeof(fernet_t));
  if (!ret) goto out;

  rc = base64_url_decode(key, len, tmp, &klen);
  if (rc == FAILURE) goto out;
  assert(klen == FERNET_KEY_BYTES);

  p = tmp;
  ret->skey = (uint8_t *)calloc(FERNET_SIGNING_KEY_BYTES, sizeof(uint8_t));
  if (!(ret->skey)) goto out;
  memcpy(ret->skey, p, FERNET_SIGNING_KEY_BYTES);
  ret->sklen = FERNET_SIGNING_KEY_BYTES;
  p += FERNET_SIGNING_KEY_BYTES;
  dprint(DPI_DEBUG_CIRCUIT, "Signing Key", (ret->skey), 0, (ret->sklen), 16);

  ret->ekey = (uint8_t *)calloc(FERNET_ENCRYPTION_KEY_BYTES, sizeof(uint8_t));
  if (!(ret->ekey)) goto out;
  memcpy(ret->ekey, p, FERNET_ENCRYPTION_KEY_BYTES);
  ret->eklen = FERNET_ENCRYPTION_KEY_BYTES;
  dprint(DPI_DEBUG_CIRCUIT, "Encryption Key", (ret->ekey), 0, (ret->eklen), 16);

out:
  ffinish("ret: %p", ret);
  return ret;
}

void free_fernet(fernet_t *fernet)
{
  fstart("fernet: %p", fernet);

  if (fernet)
  {
    if (fernet->skey)
    {
      fernet->sklen = 0;
      free(fernet->skey);
    }

    if (fernet->ekey)
    {
      fernet->eklen = 0;
      free(fernet->ekey);
    }

    free(fernet);
  }

  ffinish();
}

int fernet_generate_key(uint8_t *key, int *klen)
{
  fstart("klen: %p", klen);
  assert(klen != NULL);

  int ret, rc;
  uint8_t tmp[FERNET_KEY_BYTES] = {0, };

  ret = FAILURE;
  rc = RAND_bytes(tmp, FERNET_KEY_BYTES);
  if (rc != 1) goto out;
  dprint(DPI_DEBUG_CIRCUIT, "Generated Fernet Key", tmp, 0, FERNET_KEY_BYTES, 16);

  rc = base64_url_encode(tmp, FERNET_KEY_BYTES, key, klen);
  dprint(DPI_DEBUG_CIRCUIT, "Base64-encoded Fernet Key", key, 0, (*klen), 16);
  
  ret = SUCCESS;
out:
  ffinish("ret: %p", ret);
  return ret;
}

int fernet_encryption(fernet_t *fernet, uint8_t *in, int ilen, uint8_t *out, int *olen)
{
  fstart("fernet: %p, in: %p, ilen: %d, out: %p, olen: %p", fernet, in, ilen, out, olen);
  assert(fernet != NULL);
  assert(in != NULL);
  assert(ilen > 0);
  assert(out != NULL);
  assert(olen != NULL);

  int rc, ret, tlen, clen;
  unsigned long t;
  unsigned int hlen;
  uint8_t iv[FERNET_IV_LENGTH] = {0, };
  uint8_t hmac[FERNET_HMAC_LENGTH] = {0, };
  uint8_t ciph[BUF_SIZE] = {0, };
  uint8_t tmp[BUF_SIZE] = {0, };
  uint8_t *p;
  EVP_CIPHER_CTX *ectx;
  EVP_MD_CTX *mctx;
  EVP_PKEY *mkey;

  ret = FAILURE;
  ectx = mctx = mkey = NULL;
  t = time(NULL);
  clen = 0;

  dprint(DPI_DEBUG_CIRCUIT, "Message to be encrypted", in, 0, ilen, 16);
  dmsg(DPI_DEBUG_CIRCUIT, "Timestamp: %08lx", t);

  rc = RAND_bytes(iv, FERNET_IV_LENGTH);
  if (rc != 1) goto out;
  dprint(DPI_DEBUG_CIRCUIT, "Initialization Vector", iv, 0, FERNET_IV_LENGTH, 16);

  ectx = EVP_CIPHER_CTX_new();
  if (!ectx) goto out;
  rc = EVP_EncryptInit_ex(ectx, EVP_aes_128_cbc(), NULL, fernet->ekey, iv);
  if (rc != 1) goto out;

  rc = EVP_EncryptUpdate(ectx, ciph, &tlen, in, ilen);
  if (rc != 1) goto out;
  clen += tlen;

  rc = EVP_EncryptFinal_ex(ectx, ciph + tlen, &tlen);
  if (rc != 1) goto out;
  clen += tlen;
  dprint(DPI_DEBUG_CIRCUIT, "Ciphertext", ciph, 0, clen, 16);

  // Fernet Token (basic part)
  p = tmp;
  *(p++) = 0x80;                    // Version
  VAR_TO_PTR_8BYTES(t, p);          // Timestamp
  p += 8;
  memcpy(p, iv, FERNET_IV_LENGTH);  // IV
  p += FERNET_IV_LENGTH;
  memcpy(p, ciph, clen);             // Ciphertext
  p += clen;
  dprint(DPI_DEBUG_CIRCUIT, "Basic part of a token", tmp, 0, (p-tmp), 16);
  
  // HMAC
  tlen = p - tmp;
  mctx = EVP_MD_CTX_new();
  if (!mctx) goto out;

  mkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, fernet->skey, fernet->sklen);
  if (!mkey) goto out;
  
  rc = EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, mkey);
  if (rc != 1) goto out;

  rc = EVP_DigestSignUpdate(mctx, tmp, tlen);
  if (rc != 1) goto out;
  dprint(DPI_DEBUG_CIRCUIT, "MACed Message", tmp, 0, tlen, 16);

  rc = EVP_DigestSignFinal(mctx, hmac, &hlen);
  if (rc != 1) goto out;
  assert(hlen == FERNET_HMAC_LENGTH);
  dprint(DPI_DEBUG_CIRCUIT, "HMAC", hmac, 0, hlen, 16);

  memcpy(p, hmac, hlen);
  p += hlen;
  tlen = p - tmp;
  dprint(DPI_DEBUG_CIRCUIT, "Token", tmp, 0, tlen, 16);

  rc = base64_url_encode(tmp, tlen, out, olen);
  if (rc != SUCCESS) goto out;

  dmsg(DPI_DEBUG_CIRCUIT, "Base64-encoded token (%d bytes): %s", (*olen), out);

  ret = SUCCESS;
out:
  if (ectx)
    EVP_CIPHER_CTX_free(ectx);
  if (mctx)
    EVP_MD_CTX_free(mctx);
  if (mkey)
    EVP_PKEY_free(mkey);
  ffinish("ret: %d", ret);
  return ret;
}

int fernet_decryption(fernet_t *fernet, uint8_t *in, int ilen, uint8_t *out, int *olen)
{
  fstart("fernet: %p, in: %p, ilen: %d, out: %p, olen: %p", fernet, in, ilen, out, olen);
  assert(fernet != NULL);
  assert(in != NULL);
  assert(ilen > 0);
  assert(out != NULL);
  assert(olen != NULL);

  int rc, ret, tlen, clen;
  unsigned long t, rt;
  unsigned int hlen;
  uint8_t iv[FERNET_IV_LENGTH] = {0, };
  uint8_t hmac[FERNET_HMAC_LENGTH] = {0, };
  uint8_t tmp[BUF_SIZE] = {0, };
  uint8_t *p, *rhmac, *ciph;
  EVP_CIPHER_CTX *dctx;
  EVP_MD_CTX *mctx;
  EVP_PKEY *mkey;

  ret = FAILURE;
  dctx = mctx = mkey = NULL;
  t = time(NULL);
  (*olen) = 0;

  dmsg(DPI_DEBUG_CIRCUIT, "Received base64-encoded token (%d bytes): %s", ilen, in);

  rc = base64_url_decode(in, ilen, tmp, &tlen);
  if (rc != SUCCESS) goto out;
  dprint(DPI_DEBUG_CIRCUIT, "Received Token", tmp, 0, tlen, 16);

  // Version
  p = tmp;
  assert(*p == 0x80);
  dmsg(DPI_DEBUG_CIRCUIT, "Version: %02x", *p);
  p++;

  // Timestamp
  PTR_TO_VAR_8BYTES(p, rt);
  dmsg(DPI_DEBUG_CIRCUIT, "Current Timestamp: %08lx, Received Timestamp: %08lx", t, rt);
  p += 8;
  
  // HMAC
  rhmac = tmp + tlen - FERNET_HMAC_LENGTH;

  mctx = EVP_MD_CTX_new();
  if (!mctx) goto out;

  mkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, fernet->skey, fernet->sklen);
  if (!mkey) goto out;
  
  rc = EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, mkey);
  if (rc != 1) goto out;

  rc = EVP_DigestSignUpdate(mctx, tmp, tlen - FERNET_HMAC_LENGTH);
  if (rc != 1) goto out;
  dprint(DPI_DEBUG_CIRCUIT, "MACed Message", tmp, 0, (tlen - FERNET_HMAC_LENGTH), 16);

  rc = EVP_DigestSignFinal(mctx, hmac, &hlen);
  if (rc != 1) goto out;
  assert(hlen == FERNET_HMAC_LENGTH);

  dprint(DPI_DEBUG_CIRCUIT, "Received HMAC", rhmac, 0, FERNET_HMAC_LENGTH, 16);
  dprint(DPI_DEBUG_CIRCUIT, "Generated HMAC", hmac, 0, FERNET_HMAC_LENGTH, 16);

  if (strncmp((const char *)hmac, (const char *)rhmac, FERNET_HMAC_LENGTH))
  {
    emsg("HMAC error in fernet decryption");
    goto out;
  }
  else
  {
    dmsg(DPI_DEBUG_CIRCUIT, "HMAC verification success");
  }

  // IV
  memcpy(iv, p, FERNET_IV_LENGTH);
  dprint(DPI_DEBUG_CIRCUIT, "Initialization Vector", iv, 0, FERNET_IV_LENGTH, 16);
  p += FERNET_IV_LENGTH;

  // Decryption
  ciph = p;
  clen = tlen - (p - tmp) - FERNET_HMAC_LENGTH;
  dprint(DPI_DEBUG_CIRCUIT, "Ciphertext", ciph, 0, clen, 16);
  dctx = EVP_CIPHER_CTX_new();
  if (!dctx) goto out;
  rc = EVP_DecryptInit_ex(dctx, EVP_aes_128_cbc(), NULL, fernet->ekey, iv);
  if (rc != 1) goto out;

  rc = EVP_DecryptUpdate(dctx, out, &tlen, ciph, clen);
  if (rc != 1) goto out;
  (*olen) += tlen;

  rc = EVP_DecryptFinal_ex(dctx, out + tlen, &tlen);
  if (rc != 1) goto out;
  (*olen) += tlen;
  dprint(DPI_DEBUG_CIRCUIT, "Plaintext", out, 0, (*olen), 16);

  ret = SUCCESS;
out:
  if (dctx)
    EVP_CIPHER_CTX_free(dctx);
  if (mctx)
    EVP_MD_CTX_free(mctx);
  if (mkey)
    EVP_PKEY_free(mkey);
  ffinish("ret: %d", ret);
  return ret;
}
