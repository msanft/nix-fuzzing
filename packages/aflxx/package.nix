{
  lib,
  aflplusplus,
  clang_19,
  gcc14,
  llvm_19,
  llvmPackages_19,
  persistentReplay ? true,
}:
(aflplusplus.override {
  clang = clang_19;
  gcc = gcc14;
  llvm = llvm_19;
  llvmPackages = llvmPackages_19;
}).overrideAttrs
  (oldAttrs: {
    postPatch =
      oldAttrs.postPatch
      + lib.optionalString persistentReplay ''
        substituteInPlace include/config.h \
          --replace-fail '// #define AFL_PERSISTENT_RECORD' '#define AFL_PERSISTENT_RECORD'
      '';
  })
