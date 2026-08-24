// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static int expect_chroot_denied(const char *path)
{
	errno = 0;
	if (chroot(path) == -1 && errno == EPERM) {
		return 0;
	}

	fprintf(stderr, "chroot was not denied with EPERM: %s\n",
		strerror(errno));
	return -1;
}

static int run_checks(const char *self)
{
	char file[] = "/tmp/apparmor-enforce-file-XXXXXX";
	char directory[] = "/tmp/apparmor-enforce-dir-XXXXXX";
	char reexec[128];
	int fd = mkstemp(file);
	int status;
	pid_t child;

	if (fd < 0 || fchown(fd, 1, 1) < 0 || close(fd) < 0 ||
	    unlink(file) < 0) {
		perror("allowed fchown");
		return EXIT_FAILURE;
	}
	if (!mkdtemp(directory) || expect_chroot_denied(directory) < 0) {
		return EXIT_FAILURE;
	}

	child = fork();
	if (child < 0) {
		perror("fork");
		return EXIT_FAILURE;
	}
	if (child == 0) {
		_exit(expect_chroot_denied(directory) == 0 ? EXIT_SUCCESS :
							     EXIT_FAILURE);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != EXIT_SUCCESS) {
		fprintf(stderr, "inherited label did not deny chroot\n");
		return EXIT_FAILURE;
	}
	if (snprintf(reexec, sizeof(reexec), "/tmp/apparmor-reexec-%ld",
		     (long)getpid()) < 0 ||
	    symlink(self, reexec) < 0) {
		perror("create reexec symlink");
		return EXIT_FAILURE;
	}
	child = fork();
	if (child == 0) {
		execl(reexec, reexec, "--after-reexec", directory, NULL);
		perror("reexec unprofiled path");
		_exit(EXIT_FAILURE);
	}
	if (child < 0 || waitpid(child, &status, 0) != child ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
		fprintf(stderr,
			"label was not preserved across unprofiled exec\n");
		return EXIT_FAILURE;
	}
	if (unlink(reexec) < 0) {
		perror("unlink reexec symlink");
		return EXIT_FAILURE;
	}
	if (rmdir(directory) < 0) {
		perror("rmdir");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	if (argc == 3 && strcmp(argv[1], "--after-reexec") == 0) {
		return expect_chroot_denied(argv[2]) == 0 ? EXIT_SUCCESS :
							    EXIT_FAILURE;
	}
	if (argc == 2 && strcmp(argv[1], "--traceme") == 0) {
		errno = 0;
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1 &&
		    errno == EPERM) {
			return EXIT_SUCCESS;
		}
		fprintf(stderr, "ptrace was not denied with EPERM: %s\n",
			strerror(errno));
		return EXIT_FAILURE;
	}
	if (argc != 1) {
		fprintf(stderr, "usage: %s [--traceme]\n", argv[0]);
		return EXIT_FAILURE;
	}

	return run_checks(argv[0]);
}
