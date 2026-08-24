// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <ctype.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/capability.h"

#define CMDLINE_BUFFER_SIZE 4096

static const char *CMDLINE_PATH = "/proc/cmdline";
static const char *SECURITYFS_PATH = "/sys/kernel/security";
static const char *UNSELECTED_MOUNT_PATH = "/tmp/securityfs-mount";
static const char *LOAD_PATH = "/sys/kernel/security/apparmor/.load";
static const char *POLICY_PATH = "/test/security/lsm/apparmor.policy";
static const char *ENFORCE_PATH = "/test/security/lsm/apparmor-enforce";
static const char *COMPLAIN_PATH = "/test/security/lsm/apparmor-complain";

static void read_cmdline(char cmdline[CMDLINE_BUFFER_SIZE])
{
	int fd = CHECK(open(CMDLINE_PATH, O_RDONLY));
	ssize_t len = CHECK(read(fd, cmdline, CMDLINE_BUFFER_SIZE - 1));

	cmdline[len] = '\0';
	CHECK(close(fd));
}

static char *trim(char *string)
{
	char *end;

	while (isspace((unsigned char)*string)) {
		string++;
	}
	end = string + strlen(string);
	while (end > string && isspace((unsigned char)*(end - 1))) {
		end--;
	}
	*end = '\0';
	return string;
}

static bool find_effective_param(const char *name,
				 char value[CMDLINE_BUFFER_SIZE])
{
	char cmdline[CMDLINE_BUFFER_SIZE];
	char *saveptr = NULL;
	size_t name_len = strlen(name);
	bool found = false;

	read_cmdline(cmdline);
	for (char *token = strtok_r(cmdline, " \n", &saveptr); token;
	     token = strtok_r(NULL, " \n", &saveptr)) {
		if (strncmp(token, name, name_len) != 0 ||
		    token[name_len] != '=') {
			continue;
		}
		CHECK_WITH(snprintf(value, CMDLINE_BUFFER_SIZE, "%s",
				    token + name_len + 1),
			   _ret >= 0 && _ret < CMDLINE_BUFFER_SIZE);
		found = true;
	}

	return found;
}

static bool list_contains(const char *list, const char *name)
{
	char copy[CMDLINE_BUFFER_SIZE];
	char *saveptr = NULL;

	CHECK_WITH(snprintf(copy, sizeof(copy), "%s", list),
		   _ret >= 0 && _ret < (int)sizeof(copy));
	for (char *item = strtok_r(copy, ",", &saveptr); item;
	     item = strtok_r(NULL, ",", &saveptr)) {
		if (strcmp(trim(item), name) == 0) {
			return true;
		}
	}
	return false;
}

static bool apparmor_selected(void)
{
	char value[CMDLINE_BUFFER_SIZE] = "";

	if (find_effective_param("lsm", value)) {
		return list_contains(value, "apparmor");
	}
	if (find_effective_param("security", value)) {
		return strcmp(trim(value), "apparmor") == 0;
	}
	return false;
}

static unsigned char *read_policy(size_t *size)
{
	struct stat statbuf;
	unsigned char *blob;
	size_t consumed = 0;
	int fd = CHECK(open(POLICY_PATH, O_RDONLY));

	CHECK(fstat(fd, &statbuf));
	CHECK_WITH(statbuf.st_size, _ret > 0 && (uintmax_t)_ret <= SIZE_MAX);
	*size = (size_t)statbuf.st_size;
	blob = CHECK_WITH(malloc(*size), _ret != NULL);
	while (consumed < *size) {
		ssize_t count =
			CHECK(read(fd, blob + consumed, *size - consumed));

		CHECK_WITH(count, _ret > 0);
		consumed += (size_t)count;
	}
	CHECK(close(fd));
	return blob;
}

static ssize_t write_policy(const unsigned char *blob, size_t size,
			    off_t offset)
{
	int fd = open(LOAD_PATH, O_WRONLY);
	int saved_errno;
	ssize_t result;

	if (fd < 0) {
		return -1;
	}
	result = offset ? pwrite(fd, blob, size, offset) :
			  write(fd, blob, size);
	saved_errno = errno;
	if (close(fd) < 0 && result >= 0) {
		return -1;
	}
	errno = saved_errno;
	return result;
}

static int run_target(const char *path, const char *argument)
{
	int status;
	pid_t child = CHECK(fork());

	if (child == 0) {
		if (argument) {
			execl(path, path, argument, NULL);
		} else {
			execl(path, path, NULL);
		}
		perror("exec target");
		_exit(EXIT_FAILURE);
	}
	CHECK_WITH(waitpid(child, &status, 0), _ret == child);
	return WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS ? 0 :
									  -1;
}

static int test_unselected(void)
{
	struct stat statbuf;

	CHECK_WITH(stat(SECURITYFS_PATH, &statbuf),
		   _ret < 0 && errno == ENOENT);
	CHECK(mkdir(UNSELECTED_MOUNT_PATH, 0700));
	CHECK_WITH(mount("none", UNSELECTED_MOUNT_PATH, "securityfs", 0, NULL),
		   _ret < 0 && errno == ENODEV);
	CHECK(rmdir(UNSELECTED_MOUNT_PATH));
	return 0;
}

static int test_selected(void)
{
	static const unsigned char malformed[] = "bad";
	char complain_directory[] = "/tmp/apparmor-complain-dir-XXXXXX";
	unsigned char *blob;
	size_t blob_size;
	pid_t child;
	int status;

	CHECK(mount("none", SECURITYFS_PATH, "securityfs", 0, NULL));
	blob = read_policy(&blob_size);

	CHECK_WITH(write_policy(malformed, sizeof(malformed) - 1, 1),
		   _ret < 0 && errno == EINVAL);
	CHECK_WITH(write_policy(malformed, sizeof(malformed) - 1, 0),
		   _ret < 0 && errno == EPROTO);

	child = CHECK(fork());
	if (child == 0) {
		drop_capability(CAP_MAC_ADMIN);
		_exit(write_policy(blob, blob_size, 0) < 0 && errno == EPERM ?
			      EXIT_SUCCESS :
			      EXIT_FAILURE);
	}
	CHECK_WITH(waitpid(child, &status, 0),
		   _ret == child && WIFEXITED(status) &&
			   WEXITSTATUS(status) == EXIT_SUCCESS);

	CHECK_WITH(write_policy(blob, blob_size, 0),
		   _ret == (ssize_t)blob_size);
	CHECK_WITH(write_policy(blob, blob_size, 0),
		   _ret < 0 && errno == EEXIST);
	CHECK(run_target(ENFORCE_PATH, NULL));
	CHECK_WITH(mkdtemp(complain_directory), _ret != NULL);
	CHECK(run_target(COMPLAIN_PATH, complain_directory));
	CHECK(rmdir(complain_directory));

	CHECK(run_target(ENFORCE_PATH, "--traceme"));

	free(blob);
	CHECK(umount(SECURITYFS_PATH));
	return 0;
}

FN_TEST(apparmor_selection_and_policy_enforcement)
{
	if (apparmor_selected()) {
		TEST_SUCC(test_selected());
	} else {
		TEST_SUCC(test_unselected());
	}
}
END_TEST()
