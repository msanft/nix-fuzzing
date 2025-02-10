{
  stdenv,
  python3,
}:
stdenv.mkDerivation {
  pname = "write_tracer";
  version = "0.0.1";
  src = ../../write_tracer;

  propagatedBuildInputs = [ (python3.withPackages (ps: [ ps.bcc ])) ];

  dontUnpack = true;

  installPhase = ''
    runHook preInstall

    install -Dm755 $src/write_tracer.py $out/bin/write_tracer
    
    runHook postInstall
  '';
}
