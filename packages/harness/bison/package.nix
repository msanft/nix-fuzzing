{
  aflxx-stdenv,
  m4,
  perl,
  writeText,
  makeSetupHook,
  aflxx,
  ...
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
aflxx-stdenv.mkDerivation {
  name = "bison";
  version = "3.8.2";

  configurePlatforms = [
    "build"
    "host"
  ];

  src = ./src;

  buildInputs = [
    aflSetupHook
  ];

  nativeBuildInputs = [
    m4
    perl
  ];

  propagatedBuildInputs = [ m4 ];

  doCheck = false;
  doInstallCheck = false;
}
