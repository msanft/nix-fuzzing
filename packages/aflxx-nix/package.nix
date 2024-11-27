{
  aflxx-stdenv,
  nix,
  aflxx,
  makeSetupHook,
  writeText,
  withASan ? true,
  withUBSan ? true,
}:

let
  aflSetupHook =
    makeSetupHook
      {
        name = "aflxx-setup-hook";
      }
      (
        writeText "afl-hook.sh" ''
          preConfigurePhases+=" aflSetupPhase"

          aflSetupPhase() {
            export CC=${aflxx}/bin/afl-clang-lto
            export CXX=${aflxx}/bin/afl-clang-lto++
            export AFL_USE_ASAN=${if withASan then "1" else "0"}
            export AFL_USE_UBSAN=${if withUBSan then "1" else "0"}
          }
        ''
      );
in
(nix.override {
  stdenv = aflxx-stdenv;
}).overrideAttrs
  (oldAttrs: {
    pname = "aflxx-nix";
    buildInputs = [ aflSetupHook ] ++ oldAttrs.buildInputs;
  })
