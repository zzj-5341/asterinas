#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

if [ "$(uname -s)" != Linux ]; then
	echo "AppArmor fixtures can only be generated on Linux" >&2
	exit 1
fi

parser=${APPARMOR_PARSER:-apparmor_parser}
version=$($parser --version 2>&1 | sed -n 's/^AppArmor parser version //p' | head -n 1)
if [ "$version" != 5.0.2 ]; then
	echo "apparmor_parser 5.0.2 is required (found: ${version:-unknown})" >&2
	exit 1
fi

cd "$(dirname "$0")"

compile()
{
	features_file=$1
	profile=$2
	output=$3
	shift 3
	$parser --skip-kernel-load --skip-cache --stdout --quiet \
		--zstd-compress-level=0 --features-file "$features_file" \
		"$@" "$profile" > "$output"
}

compile features demo.profile demo.bin
compile features observe.profile observe.bin
compile features multi.profile multi.bin
compile features multi-attach.profile multi-attach.bin
compile features namespace-base.profile namespaced.bin --namespace m1-test
compile features-v7 namespace-base.profile v7-empty.bin

check_fixture()
{
	file=$1
	size=$2
	hash=$3
	actual_size=$(wc -c < "$file" | tr -d ' ')
	actual_hash=$(sha256sum "$file" | cut -d ' ' -f 1)
	[ "$actual_size" = "$size" ] && [ "$actual_hash" = "$hash" ] || {
		echo "$file does not match its frozen size/hash" >&2
		exit 1
	}
}

check_fixture demo.bin 1484 f877adf70efa115213a45d16cc11ff23d48b33ef5dee337c34ba2ee9008fa3a2
check_fixture observe.bin 118 912a45cf505271eee29e01e01d6d41abbe32ee540f94a10886746c5874400c16
check_fixture multi.bin 232 b7fd47bc42e4c21592258d2e91f59c8cae1face5407cb638aa354f906775134b
check_fixture multi-attach.bin 3016 be5438f6407bbbee631214f30550754ee2f093de8ff5a0e578c0bff084a883bd
check_fixture namespaced.bin 139 887958a93d92dd22b8628e622fdbb906f8bdb4c28f985707a0b9599bd6862cc9
check_fixture v7-empty.bin 1322 41e4c6dfc12b3990c66278bffbf3ab6260948f0900a0abb0d52dfc0421913a9a

sha256sum demo.bin observe.bin multi.bin multi-attach.bin namespaced.bin \
	v7-empty.bin > SHA256SUMS
