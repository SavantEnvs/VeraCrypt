#!/usr/bin/env bash
#
# mayhem/build.sh — builds VeraCrypt's Platform/Volume/Core libraries with the fuzzing sanitizers,
# the fuzz harnesses (+ standalone reproducers) and, with the project's normal flags, the upstream
# volume-read test program that mayhem/test.sh runs.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT=/mayhem
LIBDIRS="Platform Volume Driver/Fuse Core"

# The Makefile reuses whatever objects are in the tree, so every build starts from a clean one
# (this also makes build.sh re-runnable).
vc_make() { make -C "$SRC/src" -j"$MAYHEM_JOBS" NOGUI=1 CC="$CC" CXX="$CXX" "$@"; }

# 1) Test build: project's normal flags, only the libraries the test program needs.
vc_make PROJ_DIRS="Platform Volume" clean >/dev/null
vc_make PROJ_DIRS="Platform Volume" TC_EXTRA_CFLAGS="$COVERAGE_FLAGS" TC_EXTRA_CXXFLAGS="$COVERAGE_FLAGS" TC_EXTRA_LFLAGS="$COVERAGE_FLAGS"
$CXX -std=c++11 -O2 $COVERAGE_FLAGS -DTC_UNIX -DTC_LINUX -DARGON2_NO_THREADS -D_FILE_OFFSET_BITS=64 \
    -I"$SRC/src" -I"$SRC/src/Crypto" -I"$SRC/src/Crypto/Argon2/include" -I"$SRC/src/PKCS11" \
    "$SRC/Tests/volume_read_test.cpp" "$SRC/src/Volume/Volume.a" "$SRC/src/Platform/Platform.a" \
    -pthread -ldl -o "$OUT/volume_read_test"

# 2) Sanitized, SanCov-instrumented build of the fuzzed libraries.
vc_make PROJ_DIRS="Platform Volume Driver/Fuse Core" clean >/dev/null
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
vc_make PROJ_DIRS="$LIBDIRS" TC_EXTRA_CFLAGS="$FUZZ_CFLAGS" TC_EXTRA_CXXFLAGS="$FUZZ_CFLAGS"

# 3) Harnesses: fuzzer binary + standalone reproducer each.
CXXFLAGS_H="-std=c++11 -DTC_UNIX -DTC_LINUX -DARGON2_NO_THREADS -D_FILE_OFFSET_BITS=64 \
    -I$SRC/src -I$SRC/src/Crypto -I$SRC/src/Crypto/Argon2/include -I$SRC/src/PKCS11"
SRCDIR="$SRC/src"
LIBS="-Wl,--start-group $SRCDIR/Core/Core.a $SRCDIR/Driver/Fuse/Driver.a $SRCDIR/Volume/Volume.a $SRCDIR/Platform/Platform.a -Wl,--end-group"
SYSLIBS="$(pkg-config --libs fuse 2>/dev/null || echo -lfuse) -ldl -pthread"
# Serializer registrations live in static initialisers of these objects; reference them directly so
# the linker keeps them.
REG_OBJS="$SRCDIR/Core/Unix/CoreServiceRequest.o $SRCDIR/Core/Unix/CoreServiceResponse.o \
    $SRCDIR/Core/MountOptions.o $SRCDIR/Core/HostDevice.o $SRCDIR/Core/CoreException.o \
    $SRCDIR/Volume/VolumeInfo.o $SRCDIR/Volume/VolumePassword.o $SRCDIR/Volume/VolumeException.o"

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o /tmp/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o

build_harness() {
  local name="$1" extra="${2:-}"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $CXXFLAGS_H $LIB_FUZZING_ENGINE \
      "$SRC/mayhem/$name.cpp" $extra /tmp/lsan_off.o $LIBS $SYSLIBS -o "$OUT/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $CXXFLAGS_H \
      "$SRC/mayhem/$name.cpp" /tmp/standalone_main.o $extra /tmp/lsan_off.o $LIBS $SYSLIBS -o "$OUT/$name-standalone"
}

build_harness fuzz_serializable "$REG_OBJS"
build_harness fuzz_volume_header
build_harness fuzz_tlv
build_harness fuzz_response_apdu
build_harness fuzz_xts
build_harness fuzz_hash
