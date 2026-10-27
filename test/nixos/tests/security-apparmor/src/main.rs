// SPDX-License-Identifier: MPL-2.0

//! End-to-end AppArmor M1 tests for Asterinas NixOS.

use nixos_test_framework::*;

nixos_test_main!();

#[nixos_test]
fn apparmor_parser_compile_load_and_query(nixos_shell: &mut Session) -> Result<(), Error> {
    nixos_shell.run_cmd_and_expect("apparmor_parser --version", "AppArmor parser version 5.0.2")?;
    nixos_shell.run_cmd_and_expect("cat /proc/cmdline", "lsm=apparmor,yama")?;
    nixos_shell.run_cmd_and_expect(
        "cat /sys/kernel/security/apparmor/features/policy/versions/v5",
        "yes",
    )?;

    nixos_shell
        .run_cmd(r#"printf 'profile observe flags=(complain) {\n}\n' > /tmp/observe.profile"#)?;
    nixos_shell.run_cmd_and_expect(
        "apparmor_parser --stdout /tmp/observe.profile > /tmp/observe.bin && echo compiled",
        "compiled",
    )?;
    nixos_shell.run_cmd_and_expect("wc -c /tmp/observe.bin", "118 /tmp/observe.bin")?;
    nixos_shell.run_cmd_and_expect(
        "sha256sum /tmp/observe.bin",
        "912a45cf505271eee29e01e01d6d41abbe32ee540f94a10886746c5874400c16",
    )?;

    nixos_shell.run_cmd_and_expect(
        "apparmor_parser --binary --add /tmp/observe.bin && echo loaded",
        "loaded",
    )?;
    nixos_shell.run_cmd_and_expect(
        "cat /sys/kernel/security/apparmor/profiles",
        "observe (complain)",
    )?;
    nixos_shell.run_cmd_and_expect(
        "(apparmor_parser --binary --add /tmp/observe.bin > /tmp/duplicate.log 2>&1 && false || grep -F 'File exists' /tmp/duplicate.log) && echo duplicate-rejected",
        "duplicate-rejected",
    )?;
    nixos_shell.run_cmd_and_expect(
        "cat /sys/kernel/security/apparmor/profiles",
        "observe (complain)",
    )?;

    Ok(())
}
