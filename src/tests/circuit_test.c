#include <dpi/circuit.h>
#include <dpi/debug.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>

#include <openssl/evp.h>
#define KEY_SIZE 16
#define BLOCK_SIZE 16

int usage(const char *pname)
{
  emsg(">> Usage: %s [options]", pname);
  emsg("Options");
  emsg("  -c, --circuit     Circuit file path");
  exit(1);
}

int main(int argc, char *argv[])
{
  int c, i, j, k, dtype, elen, onum, olen;
  const char *pname;
  const char *cname;
  uint8_t *obyte;
  uint8_t *obit;
  uint8_t byte;
  circuit_t *circuit;
  EVP_CIPHER_CTX *ectx;
  unsigned char key[KEY_SIZE] = 
  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  unsigned char input[BLOCK_SIZE] = 
  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00 };
  unsigned char enc[BLOCK_SIZE] = {0, };
  //unsigned char key[1] = { 0x00 };
  //unsigned char input[1] = { 0x2f };

  pname = argv[0];
  cname = NULL;
  dtype = DPI_DEBUG_CIRCUIT;

  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"circuit", required_argument, 0, 'c'},
      {0, 0, 0, 0}
    };

    const char *opt = "c:0";

    c = getopt_long(argc, argv, opt, long_options, &option_index);

    if (c == -1)
      break;
    
    switch (c)
    {
      case 'c':
        cname = optarg;
        if (access(cname, F_OK) != 0)
        {
          emsg("The file %s does not exist", cname);
          cname = NULL;
        }
        break;

      default:
        usage(pname);
    }
  }

  if (!cname)
  {
    emsg("Input circuit file should be inserted");
    usage(pname);
  }

  ectx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ectx, EVP_aes_128_ecb(), NULL, key, NULL);
  EVP_EncryptUpdate(ectx, enc, &elen, input, BLOCK_SIZE);
  EVP_CIPHER_CTX_free(ectx);

  iprint(DPI_DEBUG_CIRCUIT, "Key", key, 0, KEY_SIZE, 16);
  iprint(DPI_DEBUG_CIRCUIT, "Input", input, 0, BLOCK_SIZE, 16);
  iprint(DPI_DEBUG_CIRCUIT, "Ciphertext (EVP)", enc, 0, elen, 16);

  circuit = init_circuit(cname);
  add_input(circuit, key, KEY_SIZE);
  add_input(circuit, input, BLOCK_SIZE);
  //add_input(circuit, key, 1);
  //add_input(circuit, input, 1);

  prepare_circuit_operation(circuit);
  //proceed(circuit);
  proceed_full_depths(circuit);
  
  onum = get_num_of_outputs(circuit);
  for (i=0; i<onum; i++)
  {
    obyte = get_output_bytes(circuit, i, &olen);
    iprint(DPI_DEBUG_CIRCUIT, "Ciphertext (Circuit)", obyte, 0, olen, 16);
  }

  free_circuit(circuit);

  return 0;
}
