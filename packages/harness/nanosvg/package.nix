{
  aflxx-stdenv,
  nanosvg,
  aflxx,
  ...
}:
let

  aflxx-nanosvg =
    (nanosvg.override {
      stdenv = aflxx-stdenv;
    }).overrideAttrs
      (oldAttrs: {
        pname = "aflxx-nanosvg";
        cmakeFlags = [
          "-DCMAKE_C_COMPILER=${aflxx}/bin/afl-clang-lto"
        ];
        env = {
          AFL_LLVM_LAF_ALL = 1;
          AFL_USE_ASAN = 1;
        };
      });
in
aflxx-stdenv.mkDerivation {
  name = "nanosvg";

  src = ./.;

  nativeBuildInputs = [ aflxx-nanosvg ];

  buildPhase = ''
    runHook preBuild

    mkdir -p $out/bin
    afl-clang-lto main.c -o $out/bin/main -lm

    runHook postBuild
  '';

  env = {
    AFL_LLVM_LAF_ALL = 1;
    AFL_USE_ASAN = 1;
  };

  passthru = { inherit aflxx-nanosvg; };
}
