# SPDX-License-Identifier: MPL-2.0

SUBDIRS := \
	capability \
	lsm \
	namespace \

include ../common/Makefile

APPARMOR_POLICY_OUTPUT := $(OUTPUT_DIR)/security/lsm/apparmor.policy

all: $(APPARMOR_POLICY_OUTPUT)

$(APPARMOR_POLICY_OUTPUT): $(APPARMOR_POLICY_BLOB)
	@install -D -m 0444 "$<" "$@"
