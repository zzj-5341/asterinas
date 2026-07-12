// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../../common/capability.h"
#include <fcntl.h>
#include <linux/falloc.h>
#include <linux/securebits.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/xattr.h>

static uid_t root = 0;
static uid_t nobody = 65534;

#define CAPS_ALL "000001ffffffffff"
#define CAPS_NET_BIND_SERVICE "0000000000000400"
#define CAPS_NONE "0000000000000000"

#define SECURITY_CAPABILITY_XATTR "security.capability"

#define AST_VFS_CAP_REVISION_1 0x01000000
#define AST_VFS_CAP_REVISION_2 0x02000000
#define AST_VFS_CAP_REVISION_3 0x03000000
#define AST_VFS_CAP_FLAGS_EFFECTIVE 0x00000001

struct ast_vfs_cap_data_v1 {
	uint32_t magic_etc;
	uint32_t permitted;
	uint32_t inheritable;
};

struct ast_vfs_cap_data_v2 {
	uint32_t magic_etc;
	uint32_t permitted_low;
	uint32_t inheritable_low;
	uint32_t permitted_high;
	uint32_t inheritable_high;
};

struct ast_vfs_cap_data_v3 {
	uint32_t magic_etc;
	uint32_t permitted_low;
	uint32_t inheritable_low;
	uint32_t permitted_high;
	uint32_t inheritable_high;
	uint32_t rootid;
};

static char child_path[4096];

static int clear_caps(void)
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct data[2];

	hdr.version = _LINUX_CAPABILITY_VERSION_3;
	hdr.pid = 0;
	memset(data, 0, sizeof(data));

	return syscall(SYS_capset, &hdr, data);
}

static int add_inheritable(int capability)
{
	struct __user_cap_data_struct cap_data[2] = {};
	unsigned int cap_index = capability / 32;
	uint32_t cap_mask = 1U << (capability % 32);

	if (__read_cap_data(cap_data) < 0)
		return -1;

	cap_data[cap_index].inheritable |= cap_mask;
	return __write_cap_data(cap_data);
}

static int noop(void)
{
	return 0;
}

static char *copy_child_to_exec_template(const char *template)
{
	char *exec_path;
	char buffer[4096];
	int src_fd;
	int dst_fd;

	exec_path = CHECK_WITH(strdup(template), _ret != NULL);
	dst_fd = CHECK(mkstemp(exec_path));
	src_fd = CHECK(open(child_path, O_RDONLY));

	for (;;) {
		ssize_t read_len = CHECK(read(src_fd, buffer, sizeof(buffer)));
		ssize_t written = 0;

		if (read_len == 0) {
			break;
		}

		while (written < read_len) {
			written += CHECK(write(dst_fd, buffer + written,
					       read_len - written));
		}
	}

	CHECK(fchmod(dst_fd, 0755));
	CHECK(close(src_fd));
	CHECK(close(dst_fd));
	return exec_path;
}

static char *copy_child_to_temp_exec(void)
{
	return copy_child_to_exec_template("/tmp/file_caps_execXXXXXX");
}

static char *create_exec_with_file_caps(const void *xattr_value,
					size_t xattr_size)
{
	char *exec_path = copy_child_to_temp_exec();

	CHECK(setxattr(exec_path, SECURITY_CAPABILITY_XATTR, xattr_value,
		       xattr_size, 0));
	return exec_path;
}

static void check_file_caps_absent(const char *exec_path)
{
	char value[sizeof(struct ast_vfs_cap_data_v3)];

	CHECK_WITH(getxattr(exec_path, SECURITY_CAPABILITY_XATTR, value,
			    sizeof(value)),
		   _ret == -1 && errno == ENODATA);
}

static void check_file_caps_present(const char *exec_path)
{
	char value[sizeof(struct ast_vfs_cap_data_v3)];

	CHECK_WITH(getxattr(exec_path, SECURITY_CAPABILITY_XATTR, value,
			    sizeof(value)),
		   _ret > 0);
}

static void check_file_caps_present_fd(int fd)
{
	char value[sizeof(struct ast_vfs_cap_data_v3)];

	CHECK_WITH(fgetxattr(fd, SECURITY_CAPABILITY_XATTR, value,
			     sizeof(value)),
		   _ret > 0);
}

struct concurrent_exec_args {
	const char *exec_path;
	pthread_barrier_t *barrier;
};

static void *concurrent_exec_thread(void *arg)
{
	const struct concurrent_exec_args *args = arg;
	int barrier_result = pthread_barrier_wait(args->barrier);

	if (barrier_result != 0 &&
	    barrier_result != PTHREAD_BARRIER_SERIAL_THREAD)
		_exit(EXIT_FAILURE);

	execl(args->exec_path, args->exec_path, CAPS_NET_BIND_SERVICE,
	      CAPS_NET_BIND_SERVICE, CAPS_NONE, NULL);
	if (errno != EAGAIN)
		_exit(EXIT_FAILURE);

	for (;;)
		pause();
}

FN_SETUP(child_path)
{
	CHECK(readlink("/proc/self/exe", child_path, sizeof(child_path) - 10));
	strcat(child_path, "_child");
}
END_SETUP()

#define TEST_CAPS_AFTER_EXECVE(name, ruid, euid, suid, func, ecaps, pcaps,  \
			       icaps, at_secure)                            \
	FN_TEST(name)                                                       \
	{                                                                   \
		pid_t pid;                                                  \
		int status;                                                 \
                                                                            \
		pid = TEST_SUCC(fork());                                    \
		if (pid == 0) {                                             \
			CHECK(setresuid(ruid, euid, suid));                 \
			CHECK(func());                                      \
			CHECK(execl(child_path, child_path, ecaps, pcaps,   \
				    icaps, "0", at_secure, NULL));          \
		}                                                           \
                                                                            \
		TEST_RES(wait(&status), _ret == pid && WIFEXITED(status) && \
						WEXITSTATUS(status) == 0);  \
	}                                                                   \
	END_TEST()

// ===========================================================
// Tests whose initial state does not contain any capabilities
// ===========================================================

#define TEST_EXECVE_GAIN_CAPS(name, ruid, euid, suid, at_secure)             \
	TEST_CAPS_AFTER_EXECVE(name, ruid, euid, suid, clear_caps, CAPS_ALL, \
			       CAPS_ALL, CAPS_NONE, at_secure)

#define TEST_EXECVE_NO_GAIN_CAPS(name, ruid, euid, suid, pcaps, at_secure)    \
	TEST_CAPS_AFTER_EXECVE(name, ruid, euid, suid, clear_caps, CAPS_NONE, \
			       pcaps, CAPS_NONE, at_secure)

// Effective UID = 0
//
// Final State:
// Effective capabilities = CAPS_ALL, permitted capabilities = CAPS_ALL
TEST_EXECVE_GAIN_CAPS(rrr_gain_caps, root, root, root, "0");
TEST_EXECVE_GAIN_CAPS(rrn_gain_caps, root, root, nobody, "0");
TEST_EXECVE_GAIN_CAPS(nrr_gain_caps, nobody, root, root, "1");
TEST_EXECVE_GAIN_CAPS(nrn_gain_caps, nobody, root, nobody, "1");

// Effective UID != 0, Real UID = 0
//
// Final State:
// Effective capabilities = CAPS_NONE, permitted capabilities = CAPS_ALL
TEST_EXECVE_NO_GAIN_CAPS(rnr_no_gain_caps, root, nobody, root, CAPS_ALL, "1");
TEST_EXECVE_NO_GAIN_CAPS(rnn_no_gain_caps, root, nobody, nobody, CAPS_ALL, "1");

// Effective UID != 0, Real UID != 0
//
// Final State:
// Effective capabilities = CAPS_NONE, permitted capabilities = CAPS_NONE
TEST_EXECVE_NO_GAIN_CAPS(nnr_no_gain_caps, nobody, nobody, root, CAPS_NONE,
			 "0");
TEST_EXECVE_NO_GAIN_CAPS(nnn_no_gain_caps, nobody, nobody, nobody, CAPS_NONE,
			 "0");

// ===================================================
// Tests whose initial state contains all capabilities
// ===================================================

#define TEST_EXECVE_NO_LOST_CAPS(name, ruid, euid, suid, at_secure)    \
	TEST_CAPS_AFTER_EXECVE(name, ruid, euid, suid, noop, CAPS_ALL, \
			       CAPS_ALL, CAPS_NONE, at_secure)

#define TEST_EXECVE_LOST_CAPS(name, ruid, euid, suid, pcaps, at_secure)        \
	TEST_CAPS_AFTER_EXECVE(name, ruid, euid, suid, noop, CAPS_NONE, pcaps, \
			       CAPS_NONE, at_secure)

// Effective UID = 0
//
// Final State:
// Effective capabilities = CAPS_ALL, permitted capabilities = CAPS_ALL
TEST_EXECVE_NO_LOST_CAPS(rrr_no_lost_caps, root, root, root, "0");
TEST_EXECVE_NO_LOST_CAPS(rrn_no_lost_caps, root, root, nobody, "0");
TEST_EXECVE_NO_LOST_CAPS(nrr_no_lost_caps, nobody, root, root, "1");
TEST_EXECVE_NO_LOST_CAPS(nrn_no_lost_caps, nobody, root, nobody, "1");

// Effective UID != 0, Real UID = 0
//
// Final State:
// Effective capabilities = CAPS_NONE, permitted capabilities = CAPS_ALL
TEST_EXECVE_LOST_CAPS(rnr_lost_caps, root, nobody, root, CAPS_ALL, "1");
TEST_EXECVE_LOST_CAPS(rnn_lost_caps, root, nobody, nobody, CAPS_ALL, "1");

// Effective UID != 0, Real UID != 0
//
// Final State:
// Effective capabilities = CAPS_NONE, permitted capabilities = CAPS_NONE
TEST_EXECVE_LOST_CAPS(nnr_lost_caps, nobody, nobody, root, CAPS_NONE, "0");
TEST_EXECVE_LOST_CAPS(nnn_lost_caps, nobody, nobody, nobody, CAPS_NONE, "0");

FN_TEST(file_caps_v1_write_rejected)
{
	const struct ast_vfs_cap_data_v1 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_1 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path = copy_child_to_temp_exec();

	TEST_ERRNO(setxattr(exec_path, SECURITY_CAPABILITY_XATTR, &file_caps,
			    sizeof(file_caps), 0),
		   EINVAL);
	check_file_caps_absent(exec_path);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_v2_gain_effective_caps)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	pid_t pid;
	int status;

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK(execl(exec_path, exec_path, CAPS_NET_BIND_SERVICE,
			    CAPS_NET_BIND_SERVICE, CAPS_NONE, NULL));
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_concurrent_exec_same_process)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	pid_t pid;
	int status;

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		struct concurrent_exec_args args;
		pthread_barrier_t barrier;
		pthread_t threads[2];

		CHECK(setresuid(nobody, nobody, nobody));
		CHECK_WITH(pthread_barrier_init(&barrier, NULL, 3), _ret == 0);
		args.exec_path = exec_path;
		args.barrier = &barrier;
		CHECK_WITH(pthread_create(&threads[0], NULL,
					  concurrent_exec_thread, &args),
			   _ret == 0);
		CHECK_WITH(pthread_create(&threads[1], NULL,
					  concurrent_exec_thread, &args),
			   _ret == 0);
		CHECK_WITH(pthread_barrier_wait(&barrier),
			   _ret == 0 || _ret == PTHREAD_BARRIER_SERIAL_THREAD);
		for (;;)
			pause();
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

// Regression for PR #3365 review: file capabilities suppress the legacy setuid-root
// effective capability grant unless the xattr effective flag is set.
FN_TEST(file_caps_setuid_root_no_legacy_effective_caps)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path = copy_child_to_temp_exec();
	pid_t pid;
	int status;

	TEST_SUCC(chmod(exec_path, 04755));
	TEST_SUCC(setxattr(exec_path, SECURITY_CAPABILITY_XATTR, &file_caps,
			   sizeof(file_caps), 0));

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK(execl(exec_path, exec_path, CAPS_NONE,
			    CAPS_NET_BIND_SERVICE, CAPS_NONE, NULL));
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_v2_gain_permitted_only_caps)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	pid_t pid;
	int status;

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK(execl(exec_path, exec_path, CAPS_NONE,
			    CAPS_NET_BIND_SERVICE, CAPS_NONE, NULL));
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_real_root_without_effective_flag)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	pid_t pid;
	int status;

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(execl(exec_path, exec_path, CAPS_ALL, CAPS_ALL, CAPS_NONE,
			    NULL));
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_clear_ambient_caps)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	pid_t pid;
	int status;

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(add_inheritable(CAP_NET_BIND_SERVICE));
		CHECK(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE,
			    CAP_NET_BIND_SERVICE, 0, 0));
		CHECK(prctl(PR_SET_SECUREBITS, SECBIT_NO_SETUID_FIXUP));
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK(execl(exec_path, exec_path, CAPS_NONE, CAPS_NONE,
			    CAPS_NET_BIND_SERVICE, NULL));
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_clear_ambient_caps_with_no_new_privs)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	pid_t pid;
	int status;

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(add_inheritable(CAP_NET_BIND_SERVICE));
		CHECK(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE,
			    CAP_NET_BIND_SERVICE, 0, 0));
		CHECK(prctl(PR_SET_SECUREBITS, SECBIT_NO_SETUID_FIXUP));
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
		CHECK(execl(exec_path, exec_path, CAPS_NONE, CAPS_NONE,
			    CAPS_NET_BIND_SERVICE, NULL));
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_effective_with_no_new_privs_sets_at_secure)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	pid_t pid;
	int status;

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
		CHECK(execl(exec_path, exec_path, CAPS_NONE, CAPS_NONE,
			    CAPS_NONE, "0", "1", NULL));
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(exec_clears_locked_keep_caps)
{
	char expected_securebits[16];
	pid_t pid;
	int status;

	TEST_RES(snprintf(expected_securebits, sizeof(expected_securebits),
			  "%x", SECBIT_KEEP_CAPS_LOCKED),
		 _ret > 0 && (size_t)_ret < sizeof(expected_securebits));

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(prctl(PR_SET_SECUREBITS,
			    SECBIT_KEEP_CAPS | SECBIT_KEEP_CAPS_LOCKED));
		CHECK(execl(child_path, child_path, CAPS_ALL, CAPS_ALL,
			    CAPS_NONE, expected_securebits, NULL));
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
END_TEST()

FN_TEST(file_caps_v3_rootid_match)
{
	const struct ast_vfs_cap_data_v3 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_3 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
		.rootid = root,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	pid_t pid;
	int status;

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK(execl(exec_path, exec_path, CAPS_NET_BIND_SERVICE,
			    CAPS_NET_BIND_SERVICE, CAPS_NONE, NULL));
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_v3_rootid_mismatch)
{
	const struct ast_vfs_cap_data_v3 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_3 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
		.rootid = 1234,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	pid_t pid;
	int status;

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK(execl(exec_path, exec_path, CAPS_NONE, CAPS_NONE,
			    CAPS_NONE, NULL));
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_execute_only)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	pid_t pid;
	int status;

	TEST_SUCC(chmod(exec_path, 0111));

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK(execl(exec_path, exec_path, CAPS_NET_BIND_SERVICE,
			    CAPS_NET_BIND_SERVICE, CAPS_NONE, NULL));
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_inheritable_path)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2,
		.inheritable_low = 1U << CAP_NET_BIND_SERVICE,
	};
	struct __user_cap_data_struct cap_data[2] = {};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	pid_t pid;
	int status;

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		read_cap_data(cap_data);
		cap_data[0].inheritable |= 1U << CAP_NET_BIND_SERVICE;
		write_cap_data(cap_data);
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK(execl(exec_path, exec_path, CAPS_NONE,
			    CAPS_NET_BIND_SERVICE, CAPS_NET_BIND_SERVICE,
			    NULL));
	}

	TEST_RES(waitpid(pid, &status, 0),
		 WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_bounding_set_eperm)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	pid_t pid;
	int status;

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(prctl(PR_CAPBSET_DROP, CAP_NET_BIND_SERVICE, 0, 0, 0));
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK(setenv("ASTER_EXECVE_MUST_NOT_RUN", "1", 1));
		CHECK_WITH(execl(exec_path, exec_path, CAPS_NONE, CAPS_NONE,
				 CAPS_NONE, NULL),
			   _ret == -1 && errno == EPERM);
		_exit(EXIT_SUCCESS);
	}

	TEST_RES(waitpid(pid, &status, 0),
		 WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_ignored_on_shebang_script)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char template[] = "/tmp/file_caps_scriptXXXXXX";
	char *script_path = TEST_RES(strdup(template), _ret != NULL);
	int script_fd = TEST_SUCC(mkstemp(script_path));
	pid_t pid;
	int status;

	TEST_RES(dprintf(script_fd, "#!%s\n", child_path), _ret > 0);
	TEST_SUCC(fchmod(script_fd, 0755));
	TEST_SUCC(close(script_fd));
	TEST_SUCC(setxattr(script_path, SECURITY_CAPABILITY_XATTR, &file_caps,
			   sizeof(file_caps), 0));

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(setenv("ASTER_EXECVE_SHEBANG", "1", 1));
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK(execl(script_path, script_path, CAPS_NONE, CAPS_NONE,
			    CAPS_NONE, NULL));
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_SUCC(unlink(script_path));
	free(script_path);
}
END_TEST()

FN_TEST(writable_shebang_script_prevents_exec)
{
	char template[] = "/tmp/writable_exec_scriptXXXXXX";
	char *script_path = TEST_RES(strdup(template), _ret != NULL);
	int script_fd = TEST_SUCC(mkstemp(script_path));
	pid_t pid;
	int status;

	TEST_RES(dprintf(script_fd, "#!/bin/sh\nexit 99\n"), _ret > 0);
	TEST_SUCC(fchmod(script_fd, 0755));

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK_WITH(execl(script_path, script_path, NULL),
			   _ret == -1 && errno == ETXTBSY);
		_exit(EXIT_SUCCESS);
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) &&
			 WEXITSTATUS(status) == EXIT_SUCCESS);
	TEST_SUCC(close(script_fd));
	TEST_SUCC(unlink(script_path));
	free(script_path);
}
END_TEST()

FN_TEST(file_caps_ignored_on_nosuid_mount)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char mount_template[] = "/tmp/file_caps_nosuidXXXXXX";
	char exec_template[4096];
	char *mount_path =
		TEST_RES(mkdtemp(mount_template), _ret == mount_template);
	char *exec_path;
	pid_t pid;
	int status;

	TEST_SUCC(mount("tmpfs", mount_path, "tmpfs", MS_NOSUID, NULL));
	TEST_RES(snprintf(exec_template, sizeof(exec_template), "%s/execXXXXXX",
			  mount_path),
		 _ret > 0 && (size_t)_ret < sizeof(exec_template));
	exec_path = copy_child_to_exec_template(exec_template);
	TEST_SUCC(setxattr(exec_path, SECURITY_CAPABILITY_XATTR, &file_caps,
			   sizeof(file_caps), 0));

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK(execl(exec_path, exec_path, CAPS_NONE, CAPS_NONE,
			    CAPS_NONE, NULL));
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
	TEST_SUCC(umount(mount_path));
	TEST_SUCC(rmdir(mount_path));
}
END_TEST()

FN_TEST(file_caps_require_setfcap)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path = copy_child_to_temp_exec();
	pid_t pid;
	int status;

	TEST_SUCC(setxattr(exec_path, SECURITY_CAPABILITY_XATTR, &file_caps,
			   sizeof(file_caps), 0));

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		drop_capability(CAP_SETFCAP);
		CHECK_WITH(setxattr(exec_path, SECURITY_CAPABILITY_XATTR,
				    &file_caps, sizeof(file_caps), 0),
			   _ret == -1 && errno == EPERM);
		CHECK_WITH(removexattr(exec_path, SECURITY_CAPABILITY_XATTR),
			   _ret == -1 && errno == EPERM);
		_exit(EXIT_SUCCESS);
	}

	TEST_RES(waitpid(pid, &status, 0),
		 WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_reject_invalid_xattr_header)
{
	const uint32_t truncated_header = AST_VFS_CAP_REVISION_2;
	const struct ast_vfs_cap_data_v2 unsupported_revision = {
		.magic_etc = 0x04000000,
	};
	const struct ast_vfs_cap_data_v2 unsupported_flags = {
		.magic_etc = AST_VFS_CAP_REVISION_2 | 0x2,
	};
	const struct ast_vfs_cap_data_v2 revision_length_mismatch = {
		.magic_etc = AST_VFS_CAP_REVISION_3,
	};
	char *exec_path = copy_child_to_temp_exec();

	TEST_ERRNO(setxattr(exec_path, SECURITY_CAPABILITY_XATTR,
			    &truncated_header, sizeof(truncated_header) - 1, 0),
		   EINVAL);
	TEST_ERRNO(setxattr(exec_path, SECURITY_CAPABILITY_XATTR,
			    &unsupported_revision, sizeof(unsupported_revision),
			    0),
		   EINVAL);
	TEST_ERRNO(setxattr(exec_path, SECURITY_CAPABILITY_XATTR,
			    &unsupported_flags, sizeof(unsupported_flags), 0),
		   EINVAL);
	TEST_ERRNO(setxattr(exec_path, SECURITY_CAPABILITY_XATTR,
			    &revision_length_mismatch,
			    sizeof(revision_length_mismatch), 0),
		   EINVAL);

	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_cleared_after_fallocate)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	int fd = TEST_SUCC(open(exec_path, O_RDWR));

	TEST_SUCC(fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0,
			    1));
	check_file_caps_absent(exec_path);

	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_cleared_after_write)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	int fd = TEST_SUCC(open(exec_path, O_WRONLY));

	TEST_RES(write(fd, "\x7f", 1), _ret == 1);
	check_file_caps_absent(exec_path);

	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_write_preserves_setid_with_fsetid)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	struct stat statbuf;
	int fd;

	TEST_SUCC(chmod(exec_path, 06755));
	fd = TEST_SUCC(open(exec_path, O_WRONLY));
	TEST_RES(write(fd, "x", 1), _ret == 1);
	TEST_SUCC(close(fd));
	check_file_caps_absent(exec_path);
	TEST_SUCC(stat(exec_path, &statbuf));
	TEST_RES(statbuf.st_mode & (S_ISUID | S_ISGID),
		 _ret == (S_ISUID | S_ISGID));

	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_cleared_after_pwrite)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	int fd = TEST_SUCC(open(exec_path, O_WRONLY));

	TEST_RES(pwrite(fd, "\x7f", 1, 0), _ret == 1);
	check_file_caps_absent(exec_path);

	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_cleared_after_truncate)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));

	TEST_SUCC(truncate(exec_path, 0));
	check_file_caps_absent(exec_path);

	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_preserved_after_failed_truncate)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path = copy_child_to_temp_exec();
	pid_t pid;
	int status;

	TEST_SUCC(chmod(exec_path, 0555));
	TEST_SUCC(setxattr(exec_path, SECURITY_CAPABILITY_XATTR, &file_caps,
			   sizeof(file_caps), 0));

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK_WITH(truncate(exec_path, 0),
			   _ret == -1 && errno == EACCES);
		_exit(EXIT_SUCCESS);
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	check_file_caps_present(exec_path);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_cleared_after_ftruncate)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	int fd = TEST_SUCC(open(exec_path, O_WRONLY));

	TEST_SUCC(ftruncate(fd, 0));
	check_file_caps_absent(exec_path);

	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_preserved_after_failed_memfd_mutations)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	struct stat statbuf;
	int fd = TEST_SUCC(memfd_create("sealed_file_caps", MFD_ALLOW_SEALING));

	TEST_RES(write(fd, "x", 1), _ret == 1);
	TEST_SUCC(fchmod(fd, 06755));
	TEST_SUCC(fsetxattr(fd, SECURITY_CAPABILITY_XATTR, &file_caps,
			    sizeof(file_caps), 0));
	TEST_ERRNO(fallocate(fd, FALLOC_FL_ZERO_RANGE, 0, 1), EOPNOTSUPP);
	check_file_caps_present_fd(fd);
	TEST_SUCC(fcntl(fd, F_ADD_SEALS,
			F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK));

	TEST_ERRNO(pwrite(fd, "y", 1, 0), EPERM);
	check_file_caps_present_fd(fd);
	TEST_ERRNO(ftruncate(fd, 2), EPERM);
	check_file_caps_present_fd(fd);
	TEST_ERRNO(fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0,
			     1),
		   EPERM);
	check_file_caps_present_fd(fd);
	TEST_SUCC(fstat(fd, &statbuf));
	TEST_RES(statbuf.st_mode & (S_ISUID | S_ISGID),
		 _ret == (S_ISUID | S_ISGID));

	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(file_caps_cleared_after_open_trunc)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	int fd = TEST_SUCC(open(exec_path, O_WRONLY | O_TRUNC));

	check_file_caps_absent(exec_path);

	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_preserved_after_failed_open_trunc)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path = copy_child_to_temp_exec();
	pid_t pid;
	int status;

	TEST_SUCC(chmod(exec_path, 0555));
	TEST_SUCC(setxattr(exec_path, SECURITY_CAPABILITY_XATTR, &file_caps,
			   sizeof(file_caps), 0));

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK_WITH(open(exec_path, O_WRONLY | O_TRUNC),
			   _ret == -1 && errno == EACCES);
		_exit(EXIT_SUCCESS);
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	check_file_caps_present(exec_path);
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_cleared_after_chown)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));

	TEST_SUCC(chown(exec_path, nobody, -1));
	check_file_caps_absent(exec_path);

	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(file_caps_cleared_after_fchown)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	int fd = TEST_SUCC(open(exec_path, O_RDONLY));

	TEST_SUCC(fchown(fd, nobody, -1));
	check_file_caps_absent(exec_path);

	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(shared_writable_mapping_prevents_exec)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	int fd = TEST_SUCC(open(exec_path, O_RDWR));
	void *mapping = TEST_SUCC(
		mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
	int status;
	pid_t pid;

	check_file_caps_present(exec_path);
	TEST_SUCC(close(fd));

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK(setenv("ASTER_EXECVE_MUST_NOT_RUN", "1", 1));
		CHECK_WITH(execl(exec_path, exec_path, CAPS_NET_BIND_SERVICE,
				 CAPS_NET_BIND_SERVICE, CAPS_NONE, NULL),
			   _ret == -1 && errno == ETXTBSY);
		_exit(EXIT_SUCCESS);
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) &&
			 WEXITSTATUS(status) == EXIT_SUCCESS);
	check_file_caps_present(exec_path);
	TEST_SUCC(munmap(mapping, 4096));
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(executable_denies_writable_open_until_process_exit)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char ready_fd_string[16];
	char release_fd_string[16];
	char byte;
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	int ready_pipe[2];
	int release_pipe[2];
	int status;
	pid_t pid;

	TEST_SUCC(pipe(ready_pipe));
	TEST_SUCC(pipe(release_pipe));
	pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(close(ready_pipe[0]));
		CHECK(close(release_pipe[1]));
		CHECK_WITH(snprintf(ready_fd_string, sizeof(ready_fd_string),
				    "%d", ready_pipe[1]),
			   _ret > 0 && (size_t)_ret < sizeof(ready_fd_string));
		CHECK_WITH(
			snprintf(release_fd_string, sizeof(release_fd_string),
				 "%d", release_pipe[0]),
			_ret > 0 && (size_t)_ret < sizeof(release_fd_string));
		CHECK(setenv("ASTER_EXECVE_READY_FD", ready_fd_string, 1));
		CHECK(setenv("ASTER_EXECVE_RELEASE_FD", release_fd_string, 1));
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK(execl(exec_path, exec_path, CAPS_NET_BIND_SERVICE,
			    CAPS_NET_BIND_SERVICE, CAPS_NONE, NULL));
	}

	TEST_SUCC(close(ready_pipe[1]));
	TEST_SUCC(close(release_pipe[0]));
	TEST_RES(read(ready_pipe[0], &byte, 1), _ret == 1);
	TEST_ERRNO(open(exec_path, O_WRONLY), ETXTBSY);
	TEST_ERRNO(open(exec_path, O_WRONLY | O_TRUNC), ETXTBSY);
	TEST_SUCC(chmod(exec_path, 0700));
	TEST_SUCC(chmod(exec_path, 0755));
	check_file_caps_present(exec_path);
	TEST_RES(write(release_pipe[1], "x", 1), _ret == 1);
	TEST_SUCC(close(ready_pipe[0]));
	TEST_SUCC(close(release_pipe[1]));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) &&
			 WEXITSTATUS(status) == EXIT_SUCCESS);

	int fd = TEST_SUCC(open(exec_path, O_WRONLY));
	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()

FN_TEST(writable_file_descriptor_prevents_exec)
{
	const struct ast_vfs_cap_data_v2 file_caps = {
		.magic_etc = AST_VFS_CAP_REVISION_2 |
			     AST_VFS_CAP_FLAGS_EFFECTIVE,
		.permitted_low = 1U << CAP_NET_BIND_SERVICE,
	};
	char *exec_path =
		create_exec_with_file_caps(&file_caps, sizeof(file_caps));
	int fd = TEST_SUCC(open(exec_path, O_WRONLY));
	int status;
	pid_t pid = TEST_SUCC(fork());

	if (pid == 0) {
		CHECK(setresuid(nobody, nobody, nobody));
		CHECK(setenv("ASTER_EXECVE_MUST_NOT_RUN", "1", 1));
		CHECK_WITH(execl(exec_path, exec_path, CAPS_NET_BIND_SERVICE,
				 CAPS_NET_BIND_SERVICE, CAPS_NONE, NULL),
			   _ret == -1 && errno == ETXTBSY);
		_exit(EXIT_SUCCESS);
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) &&
			 WEXITSTATUS(status) == EXIT_SUCCESS);
	check_file_caps_present(exec_path);
	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(exec_path));
	free(exec_path);
}
END_TEST()
