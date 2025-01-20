#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define NANOSVG_IMPLEMENTATION
#include <nanosvg/nanosvg.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
  __AFL_INIT();
  unsigned char *input_buf = __AFL_FUZZ_TESTCASE_BUF;

  while (__AFL_LOOP(10000)) {
    void *g_image = nsvgParse(input_buf, "px", 96.0f);
	if (g_image == NULL) {
		return 1;
	}
    nsvgDelete(g_image);
  }

  return 0;
}
