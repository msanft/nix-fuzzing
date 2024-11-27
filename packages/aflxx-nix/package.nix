{
  aflxx-stdenv,
  nix,
  aflxx,
  makeSetupHook,
  writeText,
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
