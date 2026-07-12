// SPDX-License-Identifier: MPL-2.0

#include <fcntl.h>
#include <linux/capability.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/test.h"

static void clear_effective_capabilities(void)
{
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
	};
	struct __user_cap_data_struct data[2] = {};

	CHECK(syscall(SYS_capget, &header, data));
	data[0].effective = 0;
	data[1].effective = 0;
	CHECK(syscall(SYS_capset, &header, data));
}

FN_TEST(fscreds_alien_access_uses_effective_capabilities)
{
	char proc_maps_path[64];
	char byte;
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
		CHECK_WITH(write(ready_pipe[1], "r", 1), _ret == 1);
		CHECK_WITH(read(release_pipe[0], &byte, 1), _ret == 1);
		_exit(EXIT_SUCCESS);
	}

	TEST_SUCC(close(ready_pipe[1]));
	TEST_SUCC(close(release_pipe[0]));
	TEST_RES(read(ready_pipe[0], &byte, 1), _ret == 1);
	clear_effective_capabilities();
	TEST_RES(snprintf(proc_maps_path, sizeof(proc_maps_path),
			  "/proc/%d/maps", pid),
		 _ret > 0 && (size_t)_ret < sizeof(proc_maps_path));
	TEST_ERRNO(open(proc_maps_path, O_RDONLY), EACCES);

	TEST_RES(write(release_pipe[1], "x", 1), _ret == 1);
	TEST_SUCC(close(ready_pipe[0]));
	TEST_SUCC(close(release_pipe[1]));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) &&
			 WEXITSTATUS(status) == EXIT_SUCCESS);
}
END_TEST()
