{
  lib,
  pkgs,
}:

let
  pkgs' = pkgs // self;
  self' = lib.packagesFromDirectoryRecursive {
    callPackage = lib.callPackageWith pkgs';
    directory = ./.;
  };
  self = self';
in
self
