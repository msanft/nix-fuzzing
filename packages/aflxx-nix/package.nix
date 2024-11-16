{
  aflxx-stdenv,
  nix,
  aflplusplus,
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
            export CC=${aflplusplus}/bin/afl-gcc
            export CXX=${aflplusplus}/bin/afl-g++
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
