{
  aflxx-stdenv,
  crun,
  aflxx,
  makeSetupHook,
  writeText,
  cov ? true,
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
  self =
    (crun.override {
      stdenv = aflxx-stdenv;
    }).overrideAttrs
      (oldAttrs: {
        pname = "aflxx-crun";
        patches = [ ./0001-Harness.patch ];
        buildInputs = [ aflSetupHook ] ++ oldAttrs.buildInputs;
        postInstall =
          if cov then
            ''
              cp *.gcno $out
            ''
          else
            "";
        NIX_CFLAGS_COMPILE = if cov then "-fprofile-arcs -ftest-coverage" else "";
      });
in
self
