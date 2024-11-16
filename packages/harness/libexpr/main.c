#include <nix_api_expr.h>
#include <nix_api_util.h>
#include <nix_api_value.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  nix_libexpr_init(NULL);

  Store *store = nix_store_open(NULL, "dummy://", NULL);
  EvalState *state =
      nix_state_create(NULL, NULL, store); // empty search path (NIX_PATH)
  Value *value = nix_alloc_value(NULL, state);

  while (__AFL_LOOP(1000)) {
    nix_expr_eval_from_string(NULL, state, argv[1], ".", value);
    nix_value_force(NULL, state, value);
  }

  nix_gc_decref(NULL, value);
  nix_state_free(state);
  nix_store_free(store);
  return 0;
}
