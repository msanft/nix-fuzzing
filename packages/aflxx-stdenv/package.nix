{
  stdenv,
  overrideCC,
  aflxx,
  wrapCCWith,
  wrapBintoolsWith,
  binutils-unwrapped,
  glibc,
}:
let
  cc = wrapCCWith {
    cc = aflxx;
    bintools = wrapBintoolsWith {
      bintools = binutils-unwrapped;
      libc = glibc;
    };
  };
in
overrideCC stdenv cc
