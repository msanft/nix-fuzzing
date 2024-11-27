{
  aflplusplus,
  clang_19,
  gcc14,
  llvm_19,
  llvmPackages_19,
}:
aflplusplus.override {
  clang = clang_19;
  gcc = gcc14;
  llvm = llvm_19;
  llvmPackages = llvmPackages_19;
}
