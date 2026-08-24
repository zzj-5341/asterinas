// SPDX-License-Identifier: MPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s directory\n", argv[0]);
		return EXIT_FAILURE;
	}
	if (chroot(argv[1]) < 0) {
		perror("complain chroot");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
