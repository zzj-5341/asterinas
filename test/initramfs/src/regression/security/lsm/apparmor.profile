profile /test/security/lsm/apparmor-enforce {
    capability chown,
    deny capability sys_chroot,
}

profile /test/security/lsm/apparmor-complain flags=(complain) {
    deny capability sys_chroot,
}
