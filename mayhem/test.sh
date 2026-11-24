#!/usr/bin/env bash
#
# mayhem/test.sh — RUN toxic's own gtest suite (src/misc_tools_test.cc, src/line_info_test.cc),
# built by mayhem/build.sh into mayhem/build-test/toxic_gtest.
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
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

RUNNER="$SRC/mayhem/build-test/toxic_gtest"
if [ ! -x "$RUNNER" ]; then
  echo "test.sh: $RUNNER missing — mayhem/build.sh must build it" >&2
  emit_ctrf "gtest" 0 1 0
  exit 1
fi
XML="$(mktemp "${TMPDIR:-/tmp}/toxic-gtest-XXXXXX.xml")"
"$RUNNER" --gtest_output="xml:$XML"
rc=$?
# Counts come from gtest's XML report: <testsuites tests="N" failures="F" disabled="D" ...>
total=$(sed -n 's/.*<testsuites tests="\([0-9]*\)".*/\1/p' "$XML" 2>/dev/null | head -1)
fails=$(sed -n 's/.*<testsuites tests="[0-9]*" failures="\([0-9]*\)".*/\1/p' "$XML" 2>/dev/null | head -1)
skipped=$(grep -c 'result="skipped"' "$XML" 2>/dev/null || true)
rm -f "$XML"
# Expect upstream's 7 tests; a runner that produces no report or fewer tests is a failure.
EXPECTED=7
if [ -z "$total" ] || [ -z "$fails" ]; then
  emit_ctrf "gtest" 0 "$EXPECTED" 0; exit 1
fi
skipped=${skipped:-0}
passed=$(( total - fails - skipped ))
missing=$(( EXPECTED > total ? EXPECTED - total : 0 ))
failed=$(( fails + missing ))
[ "$rc" -eq 0 ] || [ "$failed" -gt 0 ] || failed=1
emit_ctrf "gtest" "$passed" "$failed" "$skipped"
