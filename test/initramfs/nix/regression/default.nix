{ lib, pkgs, stdenv, callPackage, testPlatform ? "asterinas", }:
let
  scripts = lib.fileset.toSource {
    root = ./../../src/regression/scripts;
    fileset = lib.fileset.fileFilter (file: file.hasExt "sh")
      ./../../src/regression/scripts;
  };

  commonArgs = { inherit testPlatform; };
  commonBuild = dir: callPackage ./common.nix (commonArgs // { inherit dir; });

  subDirs = [
    "device"
    "fs"
    "hello_world"
    "io"
    "ipc"
    "memory"
    "process"
    "security"
    "time"
  ];

  tdxAttest = callPackage ./tdx-attest.nix { };
  apparmorPolicy = callPackage ./apparmor-policy.nix { };

  allPkgs = lib.genAttrs subDirs commonBuild // {
    network = callPackage ./common.nix (commonArgs // {
      dir = "network";
      extraAttrs = { C_FLAGS = "-I${pkgs.libnl.dev}/include/libnl3"; };
      extraBuildInputs = [ pkgs.libnl ];
    });
    security = callPackage ./common.nix (commonArgs // {
      dir = "security";
      extraAttrs = {
        APPARMOR_POLICY_BLOB = "${apparmorPolicy}/apparmor.policy";
      };
    });
  } // lib.optionalAttrs (pkgs.hostPlatform.system == "x86_64-linux") {
    intel_tdx = callPackage ./common.nix (commonArgs // {
      dir = "intel_tdx";
      extraAttrs = { TDX_ATTEST_DIR = "${tdxAttest}/QuoteGeneration"; };
    });
  };
in {
  inherit apparmorPolicy;

  package = stdenv.mkDerivation {
    pname = "regression";
    version = "0.1.0";
    buildCommand = ''
      mkdir -p $out
      cp ${scripts}/* $out

      ${lib.concatMapStringsSep "\n" (name: ''
        ln -sT "${allPkgs.${name}}/${name}" "$out/${name}"
      '') (lib.remove "security" (lib.attrNames allPkgs))}
      cp -r "${allPkgs.security}/security" "$out/security"
    '';
  };
}
