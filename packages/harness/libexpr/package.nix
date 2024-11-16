{
  aflxx-stdenv,
  aflxx-nix,
  pkg-config,
  ...
}:
aflxx-stdenv.mkDerivation {
  name = "libexpr";

  src = ./.;

  nativeBuildInputs = [
    aflxx-nix.dev
    pkg-config
  ];

  buildPhase = ''
    runHook preBuild

    mkdir -p $out/bin
    afl-gcc-fast main.c $(pkg-config nix-expr-c --libs --cflags) -o $out/bin/main

    runHook postBuild
  '';
}
