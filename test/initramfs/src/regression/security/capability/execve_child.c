// SPDX-License-Identifier: MPL-2.0

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/auxv.h>
#include <linux/capability.h>
#include <sys/prctl.h>

#include "../../common/test.h"

static uint64_t effective;
static uint64_t permitted;
static uint64_t inheritable;
static unsigned int securebits;
static int should_check_securebits;
static unsigned long at_secure;
static int should_check_at_secure;
static int parent_death_signal;
static int should_check_parent_death_signal;

static void skip_cmdline_argument(FILE *fp)
{
	while (CHECK_WITH(fgetc(fp), _ret != EOF) != '\0')
		;
}

FN_SETUP(parse_cmdline)
{
	FILE *fp;

	fp = CHECK_WITH(fopen("/proc/self/cmdline", "r"), _ret != NULL);

	skip_cmdline_argument(fp);
	if (getenv("ASTER_EXECVE_SHEBANG") != NULL)
		skip_cmdline_argument(fp);

	CHECK_WITH(fscanf(fp, "%lx\n", &effective), _ret == 1);
	CHECK_WITH(fgetc(fp), _ret == '\0');
	CHECK_WITH(fscanf(fp, "%lx\n", &permitted), _ret == 1);
	CHECK_WITH(fgetc(fp), _ret == '\0');
	CHECK_WITH(fscanf(fp, "%lx\n", &inheritable), _ret == 1);
	CHECK_WITH(fgetc(fp), _ret == '\0');

	int next = fgetc(fp);
	if (next != EOF) {
		CHECK(ungetc(next, fp));
		CHECK_WITH(fscanf(fp, "%x\n", &securebits), _ret == 1);
		CHECK_WITH(fgetc(fp), _ret == '\0');
		should_check_securebits = 1;

		next = fgetc(fp);
		if (next != EOF) {
			CHECK(ungetc(next, fp));
			CHECK_WITH(fscanf(fp, "%lu\n", &at_secure), _ret == 1);
			CHECK_WITH(fgetc(fp), _ret == '\0');
			should_check_at_secure = 1;

			next = fgetc(fp);
			if (next != EOF) {
				CHECK(ungetc(next, fp));
				CHECK_WITH(fscanf(fp, "%d\n",
						  &parent_death_signal),
					   _ret == 1);
				CHECK_WITH(fgetc(fp), _ret == '\0');
				should_check_parent_death_signal = 1;
			}
		}
	}

	CHECK(fclose(fp));
}
END_SETUP()

FN_TEST(check_exec_state)
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct data[2];

	if (getenv("ASTER_EXECVE_MUST_NOT_RUN") != NULL) {
		fprintf(stderr, "execve unexpectedly succeeded\n");
		exit(EXIT_FAILURE);
	}

	hdr.version = _LINUX_CAPABILITY_VERSION_3;
	hdr.pid = 0;

	TEST_SUCC(syscall(SYS_capget, &hdr, data));

	TEST_RES(data[0].effective | (((uint64_t)data[1].effective) << 32),
		 _ret == effective);
	TEST_RES(data[0].permitted | (((uint64_t)data[1].permitted) << 32),
		 _ret == permitted);
	TEST_RES(data[0].inheritable | (((uint64_t)data[1].inheritable) << 32),
		 _ret == inheritable);
	if (should_check_securebits)
		TEST_RES(prctl(PR_GET_SECUREBITS), _ret == securebits);
	if (should_check_at_secure)
		TEST_RES(getauxval(AT_SECURE), _ret == at_secure);
	if (should_check_parent_death_signal) {
		int actual_signal;

		TEST_SUCC(prctl(PR_GET_PDEATHSIG, &actual_signal));
		TEST_RES(actual_signal, _ret == parent_death_signal);
	}

	const char *ready_fd_string = getenv("ASTER_EXECVE_READY_FD");
	const char *release_fd_string = getenv("ASTER_EXECVE_RELEASE_FD");
	if (ready_fd_string != NULL && release_fd_string != NULL) {
		char byte;
		int ready_fd = atoi(ready_fd_string);
		int release_fd = atoi(release_fd_string);

		TEST_RES(write(ready_fd, "r", 1), _ret == 1);
		TEST_RES(read(release_fd, &byte, 1), _ret == 1);
	}
}
END_TEST()
