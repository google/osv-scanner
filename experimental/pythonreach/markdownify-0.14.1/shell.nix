{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  name = "python-shell";
  buildInputs = with pkgs; [
    python38
    python38Packages.tox
    python38Packages.setuptools
    python38Packages.virtualenv
  ];
}
