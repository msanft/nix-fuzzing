#include <nix_api_expr.h>
#include <nix_api_util.h>
#include <nix_api_value.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
  nix_libexpr_init(NULL);

  Store *store = nix_store_open(NULL, "dummy://", NULL);
  EvalState *state =
      nix_state_create(NULL, NULL, store); // empty search path (NIX_PATH)
  nix_value *value = nix_alloc_value(NULL, state);

  unsigned char *input_buf;
  __AFL_INIT();
  input_buf = __AFL_FUZZ_TESTCASE_BUF;

  while (__AFL_LOOP(1000)) {
    try {
      nix_expr_eval_from_string(NULL, state, (const char *)input_buf, ".",
                                value);
    } catch (...) {
      return 1;
    }
  }

  // TODO(msanft): imo, this is unnecessary. But clarify with upstream.
  // nix_value_force(NULL, state, value);

  nix_gc_decref(NULL, value);
  nix_state_free(state);
  nix_store_free(store);
  return 0;
}
