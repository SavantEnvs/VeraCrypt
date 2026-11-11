#!/usr/bin/env bash
#
# mayhem/test.sh — runs VeraCrypt's own volume-read test (Tests/volume_read_test.cpp, built by
# mayhem/build.sh with the normal flags) over the five Tests/test.*.hc fixtures. Each volume is
# opened with its KDF, its data area decrypted through the volume layer, and the plaintext checked
# against the SHA-256 digests upstream's Tests/test_volume_read.py pins.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

READER=/mayhem/volume_read_test
[ -x "$READER" ] || { echo "missing $READER: mayhem/build.sh did not build it" >&2; emit_ctrf "volume_read_test" 0 1 0; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/vctest.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

passed=0
failed=0

# fixture-kdf  expected SHA-256 of the decrypted data area  expected cipher
check_volume() {
  local kdf="$1" digest="$2" cipher="$3" out="$WORK/$1.plain" log="$WORK/$1.log"
  rm -f "$out"
  if "$READER" "$SRC/Tests/test.$kdf.hc" test "$kdf" "$out" >"$log" 2>&1 \
     && [ -s "$out" ] \
     && [ "$(sha256sum "$out" | cut -d' ' -f1)" = "$digest" ] \
     && grep -q "^$cipher 262144 bytes" "$log"; then
    echo "PASS $kdf"; passed=$((passed + 1))
  else
    echo "FAIL $kdf: $(head -c 300 "$log" 2>/dev/null)"; failed=$((failed + 1))
  fi
}

check_volume blake2s   21cc4f2f8db13fadca82bebb2ad574184dcbb441d447a5dee7363ceac729e0c0 AES
check_volume sha256    2b15dbe4544a853ca15311dd1dc83162c6cc06c6c470d98ca427b26093a9fb41 AES
check_volume sha512    eef460d147e613d70df39a8e6e83b624fc1d258d8ae35875caf6579a05cba95b AES
check_volume streebog  4c890502857a6360ed059c4d1dc736179fe29bffc9af72bfbff63bb691d34d82 Kuznyechik
check_volume whirlpool cb194e676678b7c40eead878df102eee0c93d453ca9d0a9e4eab7a3847edd1e0 AES

# A wrong password must be rejected and leave no plaintext.
rm -f "$WORK/wrong.plain"
if ! "$READER" "$SRC/Tests/test.sha256.hc" wrong sha256 "$WORK/wrong.plain" >"$WORK/wrong.log" 2>&1 \
   && [ ! -e "$WORK/wrong.plain" ] && grep -q "^error:" "$WORK/wrong.log"; then
  echo "PASS wrong password rejected"; passed=$((passed + 1))
else
  echo "FAIL wrong password was not rejected: $(head -c 300 "$WORK/wrong.log")"; failed=$((failed + 1))
fi

# The right password under the wrong KDF must be rejected too.
rm -f "$WORK/kdf.plain"
if ! "$READER" "$SRC/Tests/test.sha256.hc" test sha512 "$WORK/kdf.plain" >"$WORK/kdf.log" 2>&1 \
   && [ ! -e "$WORK/kdf.plain" ] && grep -q "^error:" "$WORK/kdf.log"; then
  echo "PASS wrong KDF rejected"; passed=$((passed + 1))
else
  echo "FAIL wrong KDF was not rejected: $(head -c 300 "$WORK/kdf.log")"; failed=$((failed + 1))
fi

emit_ctrf "volume_read_test" "$passed" "$failed" 0
