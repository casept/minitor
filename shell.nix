{
  system ? builtins.currentSystem,
  crossSystem ? (import <nixpkgs> {}).lib.systems.examples.musl64,
  overlays ? [ ],
}:
let
  pkgs = import <nixpkgs> {};
in
  pkgs.mkShell {
    LIBCLANG_PATH="${pkgs.llvmPackages.libclang}/lib";
    buildInputs = [
      pkgs.zlib
      pkgs.llvmPackages.libclang
      pkgs.clang_9
      pkgs.clang-tools
      pkgs.llvm_9
      pkgs.cmake
      pkgs.tor
      pkgs.nix-prefetch-git
      pkgs.kakoune
      pkgs.kak-lsp
    ];
  }
