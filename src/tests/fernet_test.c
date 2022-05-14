#include <string.h>
#include "../etc/fernet.h"
#include <dpi/debug.h>
#include <dpi/defines.h>

int main(int argc, char *argv[])
{
  fernet_t *fernet;
  int rc, klen, clen, plen;
  const uint8_t *msg = "Secret message!";
  uint8_t key[BUF_SIZE] = {0, };
  uint8_t ciph[BUF_SIZE] = {0, };
  uint8_t plain[BUF_SIZE] = {0, };

  rc = fernet_generate_key(key, &klen);
  if (rc != SUCCESS)
  {
    emsg("Generating a fernet key error");
    return 1;
  }

  fernet = init_fernet(key, klen);
  imsg(DPI_DEBUG_CIRCUIT, "Message: %s", msg);

  rc = fernet_encryption(fernet, msg, strlen(msg), ciph, &clen);
  if (rc != SUCCESS)
  {
    emsg("Encrypting a message with fernet encryption error");
    return 1;
  }
  iprint(DPI_DEBUG_CIRCUIT, "Ciphertext", ciph, 0, clen, 16);;

  rc = fernet_decryption(fernet, ciph, clen, plain, &plen);
  if (rc != SUCCESS)
  {
    emsg("Decrypting a ciphertext with ferent decryption error");
    return 1;
  }
  plain[plen] = 0;
  imsg(DPI_DEBUG_CIRCUIT, "Plaintext: %s", plain);

  free_fernet(fernet);
  return 0;
}
