#!/usr/bin/env bash
#
# mayhem/build.sh — builds libi2pd twice out of tree (sanitized for the fuzzers, normal flags for the
# upstream test programs), the seven fuzz harnesses plus their -standalone reproducers, and the tests.
# Runs inside the commit image as `mayhem` in /mayhem; air-gapped and re-runnable (it starts from a
# fresh mayhem/_build every time because lib.mk does not track header dependencies).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

B="$SRC/mayhem/_build"
rm -rf "$B"
mkdir -p "$B/tests"

COMMON="-std=c++20 -DOPENSSL_SUPPRESS_DEPRECATED -D_GLIBCXX_USE_NANOSLEEP=1 -Wno-psabi"
INC="-I$SRC/libi2pd -I$SRC/i18n -I$SRC/mayhem"
LIBS="-lboost_program_options -lssl -lcrypto -lz -lpthread -latomic"
# SanCov on the fuzzed code: $LIB_FUZZING_ENGINE only instruments the TU it links, so the library and
# every harness TU need this explicitly (also when SANITIZER_FLAGS is empty), or Mayhem records 0 edges.
COV="-fsanitize=fuzzer-no-link"
# The standalone reproducers need the SanCov callbacks too; a sanitizer runtime provides them, otherwise borrow libFuzzer's (without its main).
case "$SANITIZER_FLAGS" in *address*|*memory*|*thread*) COV_RT="" ;; *) COV_RT="$($CXX -print-file-name=libclang_rt.fuzzer_no_main-$(uname -m).a)" ;; esac
TARGETS="fuzz_http_req fuzz_http_res fuzz_http_url fuzz_routerinfo fuzz_identity fuzz_leaseset fuzz_base"

# 1) libi2pd with the project's normal flags, and the upstream test programs on top of it.
make -f mayhem/lib.mk OUT="$B/norm" LIB_CXXFLAGS="-O1 $COVERAGE_FLAGS" -j"$MAYHEM_JOBS"
# test_main wraps each test's main() so a clean return prints a marker; test.sh requires it.
$CXX -O1 $COMMON $COVERAGE_FLAGS -c mayhem/test_main.cpp -o "$B/test_main.o"
for t in tests/test-*.cpp; do
	n=$(basename "$t" .cpp)
	$CXX -O1 $COMMON $COVERAGE_FLAGS $INC -pthread -Dmain=mayhem_orig_main -fno-strict-return -Wno-return-type -c "$t" -o "$B/tests/$n.o"
	$CXX -O1 $COVERAGE_FLAGS -pthread -Wl,--unresolved-symbols=ignore-in-object-files \
		"$B/tests/$n.o" "$B/test_main.o" "$B/norm/libi2pd.a" $LIBS -o "$B/tests/$n"
done

# 2) libi2pd with sanitizers + DWARF 3, then each harness linked with libFuzzer and with the standalone driver.
make -f mayhem/lib.mk OUT="$B/san" LIB_CXXFLAGS="$SANITIZER_FLAGS $COV $DEBUG_FLAGS -O1" -j"$MAYHEM_JOBS"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
for t in $TARGETS; do
	$CXX $SANITIZER_FLAGS $COV $DEBUG_FLAGS -O1 $COMMON $INC -c "mayhem/$t.cpp" -o "$B/$t.o"
	$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/$t.o" "$B/lsan_off.o" "$B/san/libi2pd.a" \
		$LIB_FUZZING_ENGINE $LIBS -o "/mayhem/$t"
	$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/$t.o" "$B/lsan_off.o" "$B/standalone_main.o" "$B/san/libi2pd.a" \
		$COV_RT $LIBS -o "/mayhem/$t-standalone"
done
