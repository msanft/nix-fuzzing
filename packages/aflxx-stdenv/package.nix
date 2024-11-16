{
  stdenv,
  overrideCC,
  aflplusplus,
  wrapCCWith,
  wrapBintoolsWith,
  binutils-unwrapped,
  glibc,
}:
let
  cc = wrapCCWith {
    cc = aflplusplus;
    bintools = wrapBintoolsWith {
      bintools = binutils-unwrapped;
      libc = glibc;
    };
  };
in
overrideCC stdenv cc
