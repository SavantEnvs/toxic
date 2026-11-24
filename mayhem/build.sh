#!/usr/bin/env bash
# mayhem/build.sh — build toxic's fuzz harnesses (libFuzzer + one AFL driver) and its gtest suite.
# Runs in the commit image as `mayhem` in /mayhem. Toxic is built with its own Makefile three times,
# each into its own gitignored directory under mayhem/build-*/ (incremental, so a re-run is a no-op):
#   build-fuzz  sanitized + SanCov objects for the libFuzzer harnesses
#   build-afl   afl-clang-fast + sanitizers for the AFL file-input driver
#   build-test  the project's normal flags, for the upstream gtest suite (test.sh runs it)
# Harnesses link every toxic object except main.o, like upstream's bazel `libtoxic`.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${PKG_CONFIG_PATH:=/opt/toolchains/deps/toxcore-0.2.23/lib/pkgconfig}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS PKG_CONFIG_PATH

cd "$SRC"
H="$SRC/mayhem/harnesses"
LIBS="toxcore ncursesw libconfig libcurl libsodium"
FEATURES=(DISABLE_X11=1 DISABLE_AV=1 DISABLE_VI=1 DISABLE_SOUND_NOTIFY=1 DISABLE_DESKTOP_NOTIFY=1
          DISABLE_QRCODE=1 DISABLE_QRPNG=1)
# Same defines the Makefile passes (cfg/global_vars.mk, games.mk) so struct layouts match.
DEFS="-std=c11 -pthread -DHAVE_WIDECHAR -D_XOPEN_SOURCE_EXTENDED -D_FILE_OFFSET_BITS=64 -DGAMES"
DEFS="$DEFS -DTOXICVER=\"fuzz\" -DPACKAGE_DATADIR=\"/usr/local/share/toxic\" $(pkg-config --cflags $LIBS)"
LINK_LIBS="$(pkg-config --libs $LIBS) -ldl -lrt -lm -pthread"

toxic_objs() { ls "$1"/*.o | grep -v '/main\.o$'; }

# 1) Sanitized + SanCov build of toxic for the libFuzzer harnesses. The Makefile appends its own
#    `-O0 -g` after USER_CFLAGS; -gdwarf-3 keeps the DWARF version at 3 regardless.
make -j"$MAYHEM_JOBS" CC="$CC" BUILD_DIR="$SRC/mayhem/build-fuzz" LIBS="$LIBS" "${FEATURES[@]}" \
    USER_CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS" \
    USER_LDFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link"
mapfile -t FUZZ_OBJS < <(toxic_objs "$SRC/mayhem/build-fuzz")

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$SRC/mayhem/build-fuzz/lsan_off.lo"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SRC/mayhem/build-fuzz/standalone_main.lo"

for h in fuzz_settings fuzz_chat_history fuzz_misc_tools fuzz_execute fuzz_callbacks; do
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $DEFS -I"$SRC/src" -I"$H" \
        -c "$H/$h.c" -o "$SRC/mayhem/build-fuzz/$h.lo"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$SRC/mayhem/build-fuzz/$h.lo" \
        "${FUZZ_OBJS[@]}" "$SRC/mayhem/build-fuzz/lsan_off.lo" $LINK_LIBS -o "/mayhem/$h"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$SRC/mayhem/build-fuzz/standalone_main.lo" "$SRC/mayhem/build-fuzz/$h.lo" \
        "${FUZZ_OBJS[@]}" "$SRC/mayhem/build-fuzz/lsan_off.lo" $LINK_LIBS -o "/mayhem/$h-standalone"
done

# 2) AFL build (afl-clang-fast, same sanitizers) for the file-input driver: the DHT-nodes and
#    nameserver loaders keep file-static state, so each input needs a fresh process.
make -j"$MAYHEM_JOBS" CC=afl-clang-fast BUILD_DIR="$SRC/mayhem/build-afl" LIBS="$LIBS" "${FEATURES[@]}" \
    USER_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" USER_LDFLAGS="$SANITIZER_FLAGS"
mapfile -t AFL_OBJS < <(toxic_objs "$SRC/mayhem/build-afl")
afl-clang-fast $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$SRC/mayhem/build-afl/lsan_off.lo"
afl-clang-fast $SANITIZER_FLAGS $DEBUG_FLAGS $DEFS -I"$SRC/src" -I"$H" "$H/afl_file_loaders.c" \
    "${AFL_OBJS[@]}" "$SRC/mayhem/build-afl/lsan_off.lo" $LINK_LIBS -o /mayhem/afl_file_loaders

# 3) Upstream's gtest suite (src/misc_tools_test.cc, src/line_info_test.cc), normal flags.
make -j"$MAYHEM_JOBS" CC="$CC" BUILD_DIR="$SRC/mayhem/build-test" LIBS="$LIBS" "${FEATURES[@]}" \
    USER_CFLAGS="$COVERAGE_FLAGS" USER_LDFLAGS="$COVERAGE_FLAGS"
mapfile -t TEST_OBJS < <(toxic_objs "$SRC/mayhem/build-test")
$CXX -O1 $COVERAGE_FLAGS -DHAVE_WIDECHAR -D_XOPEN_SOURCE_EXTENDED -DGAMES $(pkg-config --cflags $LIBS) \
    -I"$SRC/src" "$SRC/src/misc_tools_test.cc" "$SRC/src/line_info_test.cc" "${TEST_OBJS[@]}" \
    -lgtest -lgtest_main $LINK_LIBS -o "$SRC/mayhem/build-test/toxic_gtest"
echo "build.sh: done"
