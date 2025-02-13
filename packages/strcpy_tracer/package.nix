{
  stdenv,
  python3,
}:
stdenv.mkDerivation {
  pname = "strcpy_tracer";
  version = "0.0.1";
  src = ../../strcpy_tracer;

  propagatedBuildInputs = [ (python3.withPackages (ps: [ ps.bcc ])) ];

  dontUnpack = true;

  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin

    cp -r $src/share $out
    install -Dm755 $src/strcpy_tracer.py $out/bin/strcpy_tracer

    runHook postInstall
  '';
}
