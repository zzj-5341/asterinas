// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../../common/capability.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define APPARMOR_DIR "/sys/kernel/security/apparmor"
#define LOAD_PATH APPARMOR_DIR "/.load"
#define PROFILES_PATH APPARMOR_DIR "/profiles"
#define FIXTURE_DIR "/test/security/lsm/apparmor-fixtures/"
#define MAX_POLICY_BLOB_SIZE (1024 * 1024)
#define MULTI_ATTACH_SECOND_BLOB_DATA_START 1559
#define MULTI_ATTACH_SECOND_DFA_MAGIC_OFFSET 1564

struct fixture {
	unsigned char *data;
	size_t len;
};

static bool apparmor_selected(void)
{
	char cmdline[4096];
	char *saveptr = NULL;
	bool selected = false;
	int fd = CHECK(open("/proc/cmdline", O_RDONLY));
	ssize_t len = CHECK(read(fd, cmdline, sizeof(cmdline) - 1));

	CHECK(close(fd));
	cmdline[len] = '\0';
	for (char *token = strtok_r(cmdline, " \n", &saveptr); token;
	     token = strtok_r(NULL, " \n", &saveptr)) {
		if (strncmp(token, "lsm=", 4) != 0) {
			continue;
		}

		selected = false;
		char *module_saveptr = NULL;
		for (char *module = strtok_r(token + 4, ",", &module_saveptr);
		     module; module = strtok_r(NULL, ",", &module_saveptr)) {
			if (strcmp(module, "apparmor") == 0) {
				selected = true;
			}
		}
	}

	return selected;
}

static struct fixture read_fixture(const char *name)
{
	char path[256];
	struct stat statbuf;
	struct fixture fixture;
	ssize_t total = 0;

	CHECK_WITH(snprintf(path, sizeof(path), "%s%s", FIXTURE_DIR, name),
		   _ret > 0 && (size_t)_ret < sizeof(path));
	CHECK(stat(path, &statbuf));
	fixture.len = statbuf.st_size;
	fixture.data = CHECK_WITH(malloc(fixture.len), _ret != NULL);
	int fd = CHECK(open(path, O_RDONLY));
	while ((size_t)total < fixture.len) {
		total += CHECK_WITH(read(fd, fixture.data + total,
					 fixture.len - total),
				    _ret > 0);
	}
	CHECK(close(fd));
	return fixture;
}

static ssize_t load_data_at(const void *data, size_t len, off_t offset)
{
	int fd = open(LOAD_PATH, O_WRONLY);
	if (fd < 0) {
		return -1;
	}

	ssize_t result = pwrite(fd, data, len, offset);
	int saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return result;
}

static ssize_t load_data(const void *data, size_t len)
{
	return load_data_at(data, len, 0);
}

static ssize_t read_profiles(char *output, size_t capacity)
{
	int fd = open(PROFILES_PATH, O_RDONLY);
	if (fd < 0) {
		return -1;
	}

	ssize_t result = read(fd, output, capacity - 1);
	int saved_errno = errno;
	if (result >= 0) {
		output[result] = '\0';
	}
	close(fd);
	errno = saved_errno;
	return result;
}

static int bind_privileged_port(void)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_port = htons(1),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}

	int result = bind(fd, (struct sockaddr *)&address, sizeof(address));
	int saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return result;
}

static void become_nobody_with_only_mac_admin(void)
{
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[2] = {};
	unsigned int index = CAP_MAC_ADMIN / 32;
	uint32_t mask = 1U << (CAP_MAC_ADMIN % 32);

	CHECK(prctl(PR_SET_KEEPCAPS, 1));
	CHECK(setuid(65534));
	data[index].effective = mask;
	data[index].permitted = mask;
	CHECK(syscall(SYS_capset, &header, data));
	CHECK(syscall(SYS_capget, &header, data));
	CHECK_WITH(geteuid(), _ret == 65534);
	CHECK_WITH(data[0].effective, _ret == 0);
	CHECK_WITH(data[1].effective, _ret == mask);
}

static size_t find_bytes(const unsigned char *data, size_t len,
			 const unsigned char *needle, size_t needle_len)
{
	if (needle_len > len) {
		return SIZE_MAX;
	}
	for (size_t offset = 0; offset <= len - needle_len; offset++) {
		if (memcmp(data + offset, needle, needle_len) == 0) {
			return offset;
		}
	}
	return SIZE_MAX;
}

static size_t find_dfa_magic(const unsigned char *data, size_t len)
{
	static const unsigned char magic[] = { 0x1b, 0x5e, 0x78, 0x3d };

	return find_bytes(data, len, magic, sizeof(magic));
}

#define TEST_PROFILES(expected)                                            \
	do {                                                               \
		char _profiles[512];                                       \
		TEST_RES(read_profiles(_profiles, sizeof(_profiles)),      \
			 _ret >= 0 && strcmp(_profiles, (expected)) == 0); \
	} while (0)

FN_TEST(securityfs_visibility_follows_selection)
{
	struct stat statbuf;

	TEST_RES(stat("/sys/kernel/security", &statbuf),
		 S_ISDIR(statbuf.st_mode));
	if (apparmor_selected()) {
		TEST_RES(stat(APPARMOR_DIR, &statbuf),
			 S_ISDIR(statbuf.st_mode));
	} else {
		TEST_ERRNO(stat(APPARMOR_DIR, &statbuf), ENOENT);
	}
}
END_TEST()

FN_TEST(policy_load_and_query_interface)
{
	static const char *const final_profiles = "demo (enforce)\n"
						  "demo1 (enforce)\n"
						  "demo2 (enforce)\n"
						  "observe (complain)\n";
	struct stat statbuf;

	SKIP_TEST_IF(!apparmor_selected());

	TEST_RES(stat(APPARMOR_DIR, &statbuf), S_ISDIR(statbuf.st_mode));
	TEST_RES(stat(LOAD_PATH, &statbuf), (statbuf.st_mode & 0777) == 0666);
	TEST_RES(stat(PROFILES_PATH, &statbuf),
		 (statbuf.st_mode & 0777) == 0444);
	TEST_ERRNO(stat(APPARMOR_DIR "/.replace", &statbuf), ENOENT);
	TEST_ERRNO(stat(APPARMOR_DIR "/.remove", &statbuf), ENOENT);
	TEST_ERRNO(stat(APPARMOR_DIR "/features", &statbuf), ENOENT);
	TEST_PROFILES("");
	TEST_ERRNO(load_data("", 0), EINVAL);

	int load_fd = TEST_SUCC(open(LOAD_PATH, O_WRONLY));
	char byte;
	TEST_ERRNO(read(load_fd, &byte, 1), EBADF);
	TEST_SUCC(close(load_fd));
	int profiles_fd = TEST_SUCC(open(PROFILES_PATH, O_RDONLY));
	TEST_ERRNO(write(profiles_fd, "x", 1), EBADF);
	TEST_SUCC(close(profiles_fd));
	TEST_SUCC(bind_privileged_port());

	struct fixture demo = read_fixture("demo.bin");
	struct fixture observe = read_fixture("observe.bin");
	struct fixture multi = read_fixture("multi.bin");
	struct fixture multi_attach = read_fixture("multi-attach.bin");
	struct fixture namespaced = read_fixture("namespaced.bin");
	struct fixture v7 = read_fixture("v7-empty.bin");
	TEST_RES(demo.len, _ret == 1484);
	TEST_RES(observe.len, _ret == 118);
	TEST_RES(multi.len, _ret == 232);
	TEST_RES(multi_attach.len, _ret == 3016);
	TEST_RES(namespaced.len, _ret == 139);
	TEST_RES(v7.len, _ret == 1322);

	TEST_RES(load_data(demo.data, demo.len), _ret == (ssize_t)demo.len);
	TEST_PROFILES("demo (enforce)\n");
	TEST_RES(load_data(multi_attach.data, multi_attach.len),
		 _ret == (ssize_t)multi_attach.len);
	TEST_PROFILES("demo (enforce)\ndemo1 (enforce)\ndemo2 (enforce)\n");

	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		int child_load = CHECK(open(LOAD_PATH, O_WRONLY));
		int child_profiles = CHECK(open(PROFILES_PATH, O_RDONLY));
		drop_capability(CAP_MAC_ADMIN);
		CHECK_WITH(write(child_load, demo.data, demo.len),
			   _ret < 0 && errno == EACCES);
		CHECK_WITH(pwrite(child_load, demo.data, demo.len, 1),
			   _ret < 0 && errno == EACCES);
		CHECK_WITH(read(child_profiles, &byte, 1),
			   _ret < 0 && errno == EACCES);
		CHECK(close(child_profiles));
		CHECK(close(child_load));
		_exit(EXIT_SUCCESS);
	}
	int status;
	TEST_RES(waitpid(child, &status, 0),
		 _ret == child && WIFEXITED(status) &&
			 WEXITSTATUS(status) == EXIT_SUCCESS);

	child = TEST_SUCC(fork());
	if (child == 0) {
		char profiles[512];

		become_nobody_with_only_mac_admin();
		CHECK_WITH(load_data(observe.data, observe.len),
			   _ret == (ssize_t)observe.len);
		CHECK_WITH(read_profiles(profiles, sizeof(profiles)), _ret > 0);
		CHECK_WITH(strstr(profiles, "observe (complain)\n"),
			   _ret != NULL);
		_exit(EXIT_SUCCESS);
	}
	TEST_RES(waitpid(child, &status, 0),
		 _ret == child && WIFEXITED(status) &&
			 WEXITSTATUS(status) == EXIT_SUCCESS);
	TEST_PROFILES(final_profiles);

	TEST_ERRNO(load_data_at(demo.data, demo.len, 1), ESPIPE);
	TEST_PROFILES(final_profiles);
	TEST_ERRNO(load_data(demo.data, demo.len), EEXIST);
	TEST_PROFILES(final_profiles);
	TEST_ERRNO(load_data(multi.data, multi.len), EEXIST);
	TEST_PROFILES(final_profiles);

	unsigned char *partial_conflict =
		TEST_RES(malloc(multi.len), _ret != NULL);
	memcpy(partial_conflict, multi.data, multi.len);
	static const unsigned char old_name[] = "demo2";
	static const unsigned char new_name[] = "fresh";
	size_t name_offset = find_bytes(partial_conflict, multi.len, old_name,
					sizeof(old_name) - 1);
	TEST_RES(name_offset, _ret != SIZE_MAX);
	if (name_offset != SIZE_MAX) {
		memcpy(partial_conflict + name_offset, new_name,
		       sizeof(new_name) - 1);
		TEST_ERRNO(load_data(partial_conflict, multi.len), EEXIST);
	}
	free(partial_conflict);
	TEST_PROFILES(final_profiles);

	unsigned char *duplicate = TEST_RES(malloc(demo.len * 2), _ret != NULL);
	memcpy(duplicate, demo.data, demo.len);
	memcpy(duplicate + demo.len, demo.data, demo.len);
	TEST_ERRNO(load_data(duplicate, demo.len * 2), EEXIST);
	free(duplicate);
	TEST_PROFILES(final_profiles);

	TEST_ERRNO(load_data(demo.data, demo.len - 1), EPROTO);
	TEST_PROFILES(final_profiles);

	unsigned char *corrupt = TEST_RES(malloc(demo.len), _ret != NULL);
	memcpy(corrupt, demo.data, demo.len);
	size_t magic_offset = find_dfa_magic(corrupt, demo.len);
	TEST_RES(magic_offset, _ret != SIZE_MAX);
	if (magic_offset != SIZE_MAX) {
		corrupt[magic_offset] ^= 1;
		TEST_ERRNO(load_data(corrupt, demo.len), EPROTO);
	}
	free(corrupt);
	TEST_PROFILES(final_profiles);

	TEST_RES(multi_attach.len,
		 _ret > MULTI_ATTACH_SECOND_DFA_MAGIC_OFFSET + 4);
	TEST_RES(memcmp(multi_attach.data + MULTI_ATTACH_SECOND_BLOB_DATA_START,
			"\0\0\0\0\0", 5),
		 _ret == 0);
	TEST_RES(
		memcmp(multi_attach.data + MULTI_ATTACH_SECOND_DFA_MAGIC_OFFSET,
		       "\x1b\x5e\x78\x3d", 4),
		_ret == 0);
	corrupt = TEST_RES(malloc(multi_attach.len), _ret != NULL);
	memcpy(corrupt, multi_attach.data, multi_attach.len);
	corrupt[MULTI_ATTACH_SECOND_BLOB_DATA_START] = 1;
	TEST_ERRNO(load_data(corrupt, multi_attach.len), EPROTO);
	free(corrupt);
	TEST_PROFILES(final_profiles);

	TEST_ERRNO(load_data(namespaced.data, namespaced.len), EOPNOTSUPP);
	TEST_PROFILES(final_profiles);
	TEST_ERRNO(load_data(v7.data, v7.len), EPROTONOSUPPORT);
	TEST_PROFILES(final_profiles);

	unsigned char *oversize =
		TEST_RES(malloc(MAX_POLICY_BLOB_SIZE + 1), _ret != NULL);
	memset(oversize, 0, MAX_POLICY_BLOB_SIZE + 1);
	TEST_ERRNO(load_data(oversize, MAX_POLICY_BLOB_SIZE + 1), E2BIG);
	free(oversize);
	TEST_PROFILES(final_profiles);

	load_fd = TEST_SUCC(open(LOAD_PATH, O_WRONLY));
	TEST_ERRNO(syscall(SYS_write, load_fd, (void *)(uintptr_t)-1, 1),
		   EFAULT);
	TEST_SUCC(close(load_fd));
	TEST_PROFILES(final_profiles);
	TEST_SUCC(bind_privileged_port());

	free(v7.data);
	free(namespaced.data);
	free(multi_attach.data);
	free(multi.data);
	free(observe.data);
	free(demo.data);
}
END_TEST()
