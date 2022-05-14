#include <string.h>
#include "../etc/base64.h"
#include <dpi/debug.h>

int main(int argc, char *argv[])
{
  uint8_t msg[6] = "a:aaaa";
  uint8_t out[16] = {0, };
  int ret, olen;
  
  imsg(DPI_DEBUG_CIRCUIT, "input (%d bytes): %s", 4, msg);
  iprint(DPI_DEBUG_CIRCUIT, "input", msg, 0, (strlen(msg)), 16);
  ret = base64_url_encode(msg, strlen(msg), out, &olen);
  imsg(DPI_DEBUG_CIRCUIT, "output (%d bytes): %s", olen, out);
  iprint(DPI_DEBUG_CIRCUIT, "output", out, 0, olen, 16);
  ret = base64_url_decode(out, olen, msg, &olen);
  imsg(DPI_DEBUG_CIRCUIT, "decoded (%d bytes): %s", olen, msg);
  iprint(DPI_DEBUG_CIRCUIT, "decoded", msg, 0, olen, 16);

  return 0;
}
