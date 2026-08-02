// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../../common/capability.h"
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CURRENT_ATTR_PATH_BUFFER_SIZE 128
#define LABEL_BUFFER_SIZE 256
#define POLICY_BUFFER_SIZE 2048
#define PROFILES_BUFFER_SIZE 2048

static const char *SECURITYFS_DIR = "/sys/kernel/security";
static const char *APPARMOR_LOAD_PATH = "/sys/kernel/security/apparmor/.load";
static const char *APPARMOR_PROFILES_PATH =
	"/sys/kernel/security/apparmor/profiles";
static const char *PROFILE_NAME = "asterinas-apparmor-regression";
static const char *READ_ONLY_PATH = "/tmp/apparmor-read-only";
static const char *WRITE_ONLY_PATH = "/tmp/apparmor-write-only";
static const char *DENIED_EXISTING_PATH = "/tmp/apparmor-denied-existing";
static const char *CREATE_ALLOWED_PATH = "/tmp/apparmor-create-allowed";
static const char *CREATE_READ_ONLY_PATH = "/tmp/apparmor-create-read-only";
static const char *CREATE_DENIED_PATH = "/tmp/apparmor-create-denied";
static const char *OPENAT_CREATE_ALLOWED_PATH =
	"/tmp/apparmor-openat-create-allowed";
static const char *OPENAT_CREATE_DENIED_PATH =
	"/tmp/apparmor-openat-create-denied";
static const char *CREAT_ALLOWED_PATH = "/tmp/apparmor-creat-allowed";
static const char *CREAT_DENIED_PATH = "/tmp/apparmor-creat-denied";
static const char *READ_ONLY_DIR = "/tmp/apparmor-read-only-mount";
static const char *READ_ONLY_CREATE_PATH =
	"/tmp/apparmor-read-only-mount/create";
static const char FILE_CONTENT[] = "test";
static const char *INVALID_POLICY =
	"profile apparmor-invalid-load\nrelative/path r\n";
static const char *RESERVED_NAME_POLICY =
	"profile unconfined\n/tmp/apparmor-unused r\n";
static const char *UNPRIVILEGED_POLICY =
	"profile apparmor-unprivileged-load\n/tmp/apparmor-unused r\n";

static bool securityfs_mounted_by_test;
static char current_attr_path[CURRENT_ATTR_PATH_BUFFER_SIZE];

static bool open_syscall_supported(void)
{
#ifdef SYS_open
	return true;
#else
	return false;
#endif
}

static int invoke_open_syscall(const char *path, int flags, mode_t mode)
{
#ifdef SYS_open
	return (int)syscall(SYS_open, path, flags, mode);
#else
	errno = ENOSYS;
	return -1;
#endif
}

static bool openat_syscall_supported(void)
{
#ifdef SYS_openat
	return true;
#else
	return false;
#endif
}

static int invoke_openat_syscall(const char *path, int flags, mode_t mode)
{
#ifdef SYS_openat
	return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
#else
	errno = ENOSYS;
	return -1;
#endif
}

static bool creat_syscall_supported(void)
{
#ifdef SYS_creat
	return true;
#else
	return false;
#endif
}

static int invoke_creat_syscall(const char *path, mode_t mode)
{
#ifdef SYS_creat
	return (int)syscall(SYS_creat, path, mode);
#else
	errno = ENOSYS;
	return -1;
#endif
}

static void create_file(const char *path)
{
	int fd = CHECK(open(path, O_RDWR | O_CREAT | O_TRUNC, 0600));

	CHECK_WITH(write(fd, FILE_CONTENT, sizeof(FILE_CONTENT) - 1),
		   _ret == (ssize_t)(sizeof(FILE_CONTENT) - 1));
	CHECK(close(fd));
}

static void load_profile(void)
{
	char policy[POLICY_BUFFER_SIZE];
	char profiles[PROFILES_BUFFER_SIZE];
	int policy_len;
	int fd;
	ssize_t len;

	policy_len =
		CHECK_WITH(snprintf(policy, sizeof(policy),
				    "profile %s\n"
				    "%s r\n"
				    "%s w\n"
				    "%s rw\n"
				    "%s r\n"
				    "%s rw\n"
				    "%s w\n"
				    "%s r\n",
				    PROFILE_NAME, READ_ONLY_PATH,
				    WRITE_ONLY_PATH, CREATE_ALLOWED_PATH,
				    CREATE_READ_ONLY_PATH,
				    OPENAT_CREATE_ALLOWED_PATH,
				    CREAT_ALLOWED_PATH, current_attr_path),
			   _ret >= 0 && _ret < (int)sizeof(policy));

	fd = CHECK(open(APPARMOR_LOAD_PATH, O_WRONLY));
	CHECK_WITH(write(fd, policy, (size_t)policy_len), _ret == policy_len);
	CHECK(close(fd));

	fd = CHECK(open(APPARMOR_PROFILES_PATH, O_RDONLY));
	len = CHECK(read(fd, profiles, sizeof(profiles) - 1));
	profiles[len] = '\0';
	CHECK_WITH(strstr(profiles, PROFILE_NAME), _ret != NULL);
	CHECK(close(fd));
}

static void attach_profile(void)
{
	int fd = CHECK(open(current_attr_path, O_WRONLY));
	size_t profile_name_len = strlen(PROFILE_NAME);

	CHECK_WITH(write(fd, PROFILE_NAME, profile_name_len),
		   _ret == (ssize_t)profile_name_len);
	CHECK(close(fd));
}

static int wait_for_success(pid_t pid)
{
	int status;

	if (waitpid(pid, &status, 0) != pid) {
		return -1;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		errno = ECHILD;
		return -1;
	}

	return 0;
}

FN_SETUP(prepare_apparmor_environment)
{
	CHECK_WITH(mkdir(SECURITYFS_DIR, 0755), _ret == 0 || errno == EEXIST);
	int mount_result = CHECK_WITH(mount("securityfs", SECURITYFS_DIR,
					    "securityfs", 0, NULL),
				      _ret == 0 || errno == EBUSY);
	securityfs_mounted_by_test = mount_result == 0;

	struct stat statbuf;
	CHECK(stat(APPARMOR_LOAD_PATH, &statbuf));

	CHECK_WITH(snprintf(current_attr_path, sizeof(current_attr_path),
			    "/proc/%ld/attr/current", (long)getpid()),
		   _ret >= 0 && _ret < (int)sizeof(current_attr_path));
	create_file(READ_ONLY_PATH);
	create_file(WRITE_ONLY_PATH);
	create_file(DENIED_EXISTING_PATH);
	CHECK_WITH(unlink(CREATE_ALLOWED_PATH), _ret == 0 || errno == ENOENT);
	CHECK_WITH(unlink(CREATE_READ_ONLY_PATH), _ret == 0 || errno == ENOENT);
	CHECK_WITH(unlink(CREATE_DENIED_PATH), _ret == 0 || errno == ENOENT);
	CHECK_WITH(unlink(OPENAT_CREATE_ALLOWED_PATH),
		   _ret == 0 || errno == ENOENT);
	CHECK_WITH(unlink(OPENAT_CREATE_DENIED_PATH),
		   _ret == 0 || errno == ENOENT);
	CHECK_WITH(unlink(CREAT_ALLOWED_PATH), _ret == 0 || errno == ENOENT);
	CHECK_WITH(unlink(CREAT_DENIED_PATH), _ret == 0 || errno == ENOENT);
	CHECK_WITH(mkdir(READ_ONLY_DIR, 0700), _ret == 0 || errno == EEXIST);
	CHECK(mount("ramfs", READ_ONLY_DIR, "ramfs", MS_RDONLY, NULL));
}
END_SETUP()

FN_TEST(policy_load_requires_mac_admin)
{
	pid_t child;

	child = TEST_SUCC(fork());
	if (child == 0) {
		struct __user_cap_data_struct cap_data[2] = {};
		unsigned int cap_index = CAP_MAC_ADMIN / 32;
		uint32_t cap_mask = 1U << (CAP_MAC_ADMIN % 32);

		read_cap_data(cap_data);
		CHECK_WITH(cap_data[cap_index].permitted & cap_mask, _ret != 0);
		cap_data[cap_index].effective &= ~cap_mask;
		write_cap_data(cap_data);
		read_cap_data(cap_data);
		CHECK_WITH(cap_data[cap_index].effective & cap_mask, _ret == 0);
		CHECK_WITH(cap_data[cap_index].permitted & cap_mask, _ret != 0);

		int fd = CHECK(open(APPARMOR_LOAD_PATH, O_WRONLY));

		CHECK_WITH(write(fd, UNPRIVILEGED_POLICY,
				 strlen(UNPRIVILEGED_POLICY)),
			   _ret < 0 && errno == EACCES);
		CHECK(close(fd));
		_exit(0);
	}
	if (child > 0) {
		TEST_SUCC(wait_for_success(child));
	}
}
END_TEST()

FN_TEST(policy_load_rejects_non_absolute_paths)
{
	int fd;

	fd = TEST_SUCC(open(APPARMOR_LOAD_PATH, O_WRONLY));
	if (fd >= 0) {
		TEST_ERRNO(write(fd, INVALID_POLICY, strlen(INVALID_POLICY)),
			   EINVAL);
		TEST_SUCC(close(fd));
	}
}
END_TEST()

FN_TEST(policy_load_rejects_reserved_profile_name)
{
	int fd;

	fd = TEST_SUCC(open(APPARMOR_LOAD_PATH, O_WRONLY));
	if (fd >= 0) {
		TEST_ERRNO(write(fd, RESERVED_NAME_POLICY,
				 strlen(RESERVED_NAME_POLICY)),
			   EINVAL);
		TEST_SUCC(close(fd));
	}
}
END_TEST()

/*
 * Constructor order is intentional: verify policy loading before attaching
 * the restrictive profile to this task.
 */
FN_SETUP(load_and_attach_apparmor_profile)
{
	load_profile();
	attach_profile();
}
END_SETUP()

FN_TEST(task_label_is_visible)
{
	char label[LABEL_BUFFER_SIZE];
	int fd;
	ssize_t len;

	fd = TEST_SUCC(open(current_attr_path, O_RDONLY));
	len = TEST_SUCC(read(fd, label, sizeof(label) - 1));
	if (len >= 0) {
		label[len] = '\0';
		TEST_RES(strstr(label, PROFILE_NAME), _ret != NULL);
	}
	if (fd >= 0) {
		TEST_SUCC(close(fd));
	}
}
END_TEST()

FN_TEST(profile_controls_read_access)
{
	char contents[sizeof(FILE_CONTENT) - 1];
	int fd;

	SKIP_TEST_IF(!open_syscall_supported());

	TEST_ERRNO(invoke_open_syscall(READ_ONLY_PATH, O_WRONLY, 0), EACCES);
	TEST_ERRNO(invoke_open_syscall(READ_ONLY_PATH, O_RDONLY | O_TRUNC, 0),
		   EACCES);

	fd = TEST_SUCC(invoke_open_syscall(READ_ONLY_PATH, O_RDONLY, 0));
	if (fd >= 0) {
		TEST_RES(read(fd, contents, sizeof(contents)),
			 _ret == (ssize_t)sizeof(contents));
		TEST_SUCC(close(fd));
	}
}
END_TEST()

FN_TEST(profile_allows_path_handles_without_data_access)
{
	int fd;

	SKIP_TEST_IF(!open_syscall_supported());

	fd = TEST_SUCC(invoke_open_syscall(DENIED_EXISTING_PATH, O_PATH, 0));
	if (fd >= 0) {
		TEST_SUCC(close(fd));
	}
	TEST_ERRNO(invoke_open_syscall(DENIED_EXISTING_PATH, O_RDONLY, 0),
		   EACCES);
}
END_TEST()

FN_TEST(profile_preserves_open_error_precedence)
{
	SKIP_TEST_IF(!open_syscall_supported());

	TEST_ERRNO(invoke_open_syscall("/tmp", O_WRONLY, 0), EISDIR);
	TEST_ERRNO(invoke_open_syscall(DENIED_EXISTING_PATH,
				       O_RDONLY | O_DIRECTORY, 0),
		   ENOTDIR);
	TEST_ERRNO(invoke_open_syscall(READ_ONLY_PATH,
				       O_RDONLY | O_CREAT | O_EXCL, 0600),
		   EEXIST);
	TEST_ERRNO(invoke_open_syscall(READ_ONLY_CREATE_PATH,
				       O_RDONLY | O_CREAT, 0600),
		   EROFS);
}
END_TEST()

FN_TEST(profile_controls_file_creation)
{
	struct stat statbuf;
	int fd;

	SKIP_TEST_IF(!open_syscall_supported());

	fd = TEST_SUCC(invoke_open_syscall(CREATE_ALLOWED_PATH,
					   O_RDWR | O_CREAT, 0600));
	if (fd >= 0) {
		TEST_SUCC(close(fd));
	}
	TEST_SUCC(stat(CREATE_ALLOWED_PATH, &statbuf));

	fd = TEST_SUCC(
		invoke_open_syscall(READ_ONLY_PATH, O_RDONLY | O_CREAT, 0600));
	if (fd >= 0) {
		TEST_SUCC(close(fd));
	}

	TEST_ERRNO(invoke_open_syscall(CREATE_READ_ONLY_PATH,
				       O_RDONLY | O_CREAT, 0600),
		   EACCES);
	TEST_ERRNO(stat(CREATE_READ_ONLY_PATH, &statbuf), ENOENT);
	TEST_ERRNO(invoke_open_syscall(CREATE_DENIED_PATH, O_RDONLY | O_CREAT,
				       0600),
		   EACCES);
	TEST_ERRNO(stat(CREATE_DENIED_PATH, &statbuf), ENOENT);
}
END_TEST()

FN_TEST(profile_controls_openat_access)
{
	struct stat statbuf;
	int fd;

	SKIP_TEST_IF(!openat_syscall_supported());

	fd = TEST_SUCC(
		invoke_openat_syscall(READ_ONLY_PATH, O_RDONLY, 0));
	if (fd >= 0) {
		TEST_SUCC(close(fd));
	}
	TEST_ERRNO(invoke_openat_syscall(READ_ONLY_PATH, O_WRONLY, 0),
		   EACCES);
	TEST_ERRNO(invoke_openat_syscall(READ_ONLY_PATH,
					 O_RDONLY | O_TRUNC, 0),
		   EACCES);
	TEST_RES(stat(READ_ONLY_PATH, &statbuf),
		 _ret == 0 &&
			 statbuf.st_size == (off_t)(sizeof(FILE_CONTENT) - 1));

	fd = TEST_SUCC(invoke_openat_syscall(OPENAT_CREATE_ALLOWED_PATH,
					    O_RDWR | O_CREAT, 0600));
	if (fd >= 0) {
		TEST_SUCC(close(fd));
	}
	TEST_SUCC(stat(OPENAT_CREATE_ALLOWED_PATH, &statbuf));

	TEST_ERRNO(invoke_openat_syscall(OPENAT_CREATE_DENIED_PATH,
					 O_RDONLY | O_CREAT, 0600),
		   EACCES);
	TEST_ERRNO(stat(OPENAT_CREATE_DENIED_PATH, &statbuf), ENOENT);
	TEST_ERRNO(invoke_openat_syscall("/tmp", O_TMPFILE | O_RDWR, 0600),
		   EACCES);
}
END_TEST()

FN_TEST(profile_controls_creat_access)
{
	struct stat statbuf;
	int fd;

	SKIP_TEST_IF(!creat_syscall_supported());

	fd = TEST_SUCC(invoke_creat_syscall(CREAT_ALLOWED_PATH, 0600));
	if (fd >= 0) {
		TEST_SUCC(close(fd));
	}
	TEST_RES(stat(CREAT_ALLOWED_PATH, &statbuf),
		 _ret == 0 && statbuf.st_size == 0);

	TEST_ERRNO(invoke_creat_syscall(CREAT_DENIED_PATH, 0600), EACCES);
	TEST_ERRNO(stat(CREAT_DENIED_PATH, &statbuf), ENOENT);
	TEST_ERRNO(invoke_creat_syscall(READ_ONLY_PATH, 0600), EACCES);
	TEST_RES(stat(READ_ONLY_PATH, &statbuf),
		 _ret == 0 &&
			 statbuf.st_size == (off_t)(sizeof(FILE_CONTENT) - 1));
}
END_TEST()

FN_TEST(profile_denies_unnamed_temporary_file)
{
	SKIP_TEST_IF(!open_syscall_supported());

	TEST_ERRNO(invoke_open_syscall("/tmp", O_TMPFILE | O_RDWR, 0600),
		   EACCES);
}
END_TEST()

FN_TEST(profile_controls_write_access)
{
	int fd;

	SKIP_TEST_IF(!open_syscall_supported());

	fd = TEST_SUCC(invoke_open_syscall(WRITE_ONLY_PATH, O_WRONLY, 0));
	if (fd >= 0) {
		TEST_RES(write(fd, "x", 1), _ret == 1);
		TEST_SUCC(close(fd));
	}
	TEST_ERRNO(invoke_open_syscall(WRITE_ONLY_PATH, O_RDONLY, 0), EACCES);
}
END_TEST()

FN_TEST(task_label_is_inherited)
{
	pid_t child;

	SKIP_TEST_IF(!open_syscall_supported());

	child = TEST_SUCC(fork());
	if (child == 0) {
		int fd =
			CHECK(invoke_open_syscall(READ_ONLY_PATH, O_RDONLY, 0));

		CHECK(close(fd));
		CHECK_WITH(invoke_open_syscall(READ_ONLY_PATH, O_WRONLY, 0),
			   _ret < 0 && errno == EACCES);
		_exit(0);
	}
	if (child > 0) {
		TEST_SUCC(wait_for_success(child));
	}
}
END_TEST()

/* Keep cleanup last because the preceding tests use these files and mount. */
FN_SETUP(cleanup_apparmor_environment)
{
	CHECK(unlink(READ_ONLY_PATH));
	CHECK(unlink(WRITE_ONLY_PATH));
	CHECK(unlink(DENIED_EXISTING_PATH));
	CHECK_WITH(unlink(CREATE_ALLOWED_PATH), _ret == 0 || errno == ENOENT);
	CHECK_WITH(unlink(OPENAT_CREATE_ALLOWED_PATH),
		   _ret == 0 || errno == ENOENT);
	CHECK_WITH(unlink(OPENAT_CREATE_DENIED_PATH),
		   _ret == 0 || errno == ENOENT);
	CHECK_WITH(unlink(CREAT_ALLOWED_PATH), _ret == 0 || errno == ENOENT);
	CHECK_WITH(unlink(CREAT_DENIED_PATH), _ret == 0 || errno == ENOENT);
	CHECK(umount(READ_ONLY_DIR));
	CHECK(rmdir(READ_ONLY_DIR));

	if (securityfs_mounted_by_test) {
		CHECK(umount(SECURITYFS_DIR));
	}
}
END_SETUP()
