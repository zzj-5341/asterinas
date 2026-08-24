{ pkgsBuildBuild }:
let
  source502 = pkgsBuildBuild.fetchFromGitLab {
    owner = "apparmor";
    repo = "apparmor";
    tag = "v5.0.2";
    hash = "sha256-Kuc5Nrz4iq5MC5AOcJL9Sb54DWNKlEk3b3DW0vpgSZg=";
  };

  libapparmor502 = pkgsBuildBuild.libapparmor.overrideAttrs (_: {
    version = "5.0.2";
    src = source502;
  });

  parser502 = (pkgsBuildBuild."apparmor-parser".override {
    libapparmor = libapparmor502;
  }).overrideAttrs (old: {
    buildInputs = old.buildInputs ++ [ pkgsBuildBuild.zstd ];
    doCheck = false;
    postPatch = ''
      patchShebangs .
      cd parser
      substituteInPlace Makefile \
        --replace-fail "/usr/include/linux/capability.h" \
        "${pkgsBuildBuild.linuxHeaders}/include/linux/capability.h"
    '';
  });
in pkgsBuildBuild.runCommand "apparmor-m1-policy" {
  nativeBuildInputs = [ parser502 ];
} ''
  mkdir -p "$out"
  apparmor_parser --config-file=/dev/null --jobs=1 --skip-cache \
    --kernel-features "${../../src/regression/security/lsm/apparmor.features}" \
    --policy-features "${../../src/regression/security/lsm/apparmor.features}" \
    --zstd-compress-level=0 --stdout \
    "${../../src/regression/security/lsm/apparmor.profile}" \
    > "$out/apparmor.policy"
  test -s "$out/apparmor.policy"
''
