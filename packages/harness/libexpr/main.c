#include <nix_api_expr.h>
#include <nix_api_util.h>
#include <nix_api_value.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 100

int main(int argc, char **argv) {
  nix_libexpr_init(NULL);

  Store *store = nix_store_open(NULL, "dummy://", NULL);
  EvalState *state =
      nix_state_create(NULL, NULL, store); // empty search path (NIX_PATH)
  Value *value = nix_alloc_value(NULL, state);

  char input_buf[MAX_BUF_SIZE];

  if (fgets(input_buf, MAX_BUF_SIZE, stdin) == NULL) {
    return 1;
  }

  nix_expr_eval_from_string(NULL, state, input_buf, ".", value);
  nix_value_force(NULL, state, value);

  nix_gc_decref(NULL, value);
  nix_state_free(state);
  nix_store_free(store);
  return 0;
}
