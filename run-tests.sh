#!/usr/bin/env bash
# Build and run CTest with helpful flags.
# Examples:
#   ./run_tests.sh                       # build + run all tests (Release)
#   ./run_tests.sh -d Debug              # use Debug build
#   ./run_tests.sh -r blake_hash         # only tests matching regex
#   ./run_tests.sh -L fast               # only tests with label 'fast'
#   ./run_tests.sh -j 12                 # 12 parallel test jobs
#   ./run_tests.sh -V                    # verbose test output
#   ./run_tests.sh -v                    # verbose build output
#   ./run_tests.sh --rerun-failed        # only rerun failed tests from last run
#   ./run_tests.sh --stop-on-failure     # stop on first failure
#   ./run_tests.sh --repeat-until-fail 3 # stress: repeat failing up to 3 times

set -euo pipefail

BUILD_DIR="build"
BUILD_TYPE="Release"
BUILD_VERBOSE=0
CTEST_VERBOSE=0
CTEST_JOBS=""
CTEST_REGEX=""
CTEST_EXCLUDE=""
CTEST_LABEL=""
CTEST_RERUN_FAILED=0
CTEST_STOP_ON_FAILURE=0
CTEST_REPEAT_UNTIL_FAIL=""

# sensible default jobs = #cores
DEFAULT_JOBS="$( (sysctl -n hw.ncpu 2>/dev/null || getconf _NPROCESSORS_ONLN || echo 8) )"
CTEST_JOBS="$DEFAULT_JOBS"
BUILD_JOBS="$DEFAULT_JOBS"

print_help() {
  grep '^#' "$0" | sed 's/^#\s\{0,1\}//'
  echo
  echo "Flags:"
  echo "  -d, --build-type <Release|Debug|RelWithDebInfo|MinSizeRel>"
  echo "  -b, --build-dir <dir>           (default: build)"
  echo "  -j, --jobs <N>                  parallel test jobs (default: $DEFAULT_JOBS)"
  echo "  -J, --build-jobs <N>            parallel build jobs (default: $DEFAULT_JOBS)"
  echo "  -r, --regex <REGEX>             run tests matching regex (ctest -R)"
  echo "  -E, --exclude <REGEX>           exclude tests matching regex (ctest -E)"
  echo "  -L, --label <LABEL>             run tests with label (ctest -L)"
  echo "  -V, --verbose-tests             verbose ctest (-V)"
  echo "  -v, --verbose-build             verbose build (cmake --build --verbose)"
  echo "      --rerun-failed              only rerun failed from previous run"
  echo "      --stop-on-failure           stop on first failing test"
  echo "      --repeat-until-fail <N>     repeat tests until fail or N passes"
  echo "  -h, --help"
}

# parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--build-type) BUILD_TYPE="${2:-}"; shift 2 ;;
    -b|--build-dir)  BUILD_DIR="${2:-}"; shift 2 ;;
    -j|--jobs)       CTEST_JOBS="${2:-}"; shift 2 ;;
    -J|--build-jobs) BUILD_JOBS="${2:-}"; shift 2 ;;
    -r|--regex)      CTEST_REGEX="${2:-}"; shift 2 ;;
    -E|--exclude)    CTEST_EXCLUDE="${2:-}"; shift 2 ;;
    -L|--label)      CTEST_LABEL="${2:-}"; shift 2 ;;
    -V|--verbose-tests) CTEST_VERBOSE=1; shift ;;
    -v|--verbose-build) BUILD_VERBOSE=1; shift ;;
    --rerun-failed)  CTEST_RERUN_FAILED=1; shift ;;
    --stop-on-failure) CTEST_STOP_ON_FAILURE=1; shift ;;
    --repeat-until-fail) CTEST_REPEAT_UNTIL_FAIL="${2:-}"; shift 2 ;;
    -h|--help) print_help; exit 0 ;;
    *) echo "Unknown arg: $1"; print_help; exit 1 ;;
  esac
done

# configure if needed or if build type mismatch
ensure_configured() {
  if [[ ! -f "$BUILD_DIR/CMakeCache.txt" ]]; then
    cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
    return
  fi
  # if cache has different CMAKE_BUILD_TYPE, reconfigure
  if ! grep -q "CMAKE_BUILD_TYPE:STRING=$BUILD_TYPE" "$BUILD_DIR/CMakeCache.txt" 2>/dev/null; then
    echo "Reconfiguring for build type: $BUILD_TYPE"
    cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
  fi
}

ensure_configured

echo "▶ Building ($BUILD_TYPE) ..."
BUILD_CMD=( cmake --build "$BUILD_DIR" -j "$BUILD_JOBS" )
if [[ "$BUILD_VERBOSE" -eq 1 ]]; then
  BUILD_CMD+=( --verbose )
fi
"${BUILD_CMD[@]}"

echo "▶ Running tests ..."
CTEST_CMD=( ctest --test-dir "$BUILD_DIR" -C "$BUILD_TYPE" --output-on-failure -j "$CTEST_JOBS" )

[[ -n "$CTEST_REGEX" ]]           && CTEST_CMD+=( -R "$CTEST_REGEX" )
[[ -n "$CTEST_EXCLUDE" ]]         && CTEST_CMD+=( -E "$CTEST_EXCLUDE" )
[[ -n "$CTEST_LABEL" ]]           && CTEST_CMD+=( -L "$CTEST_LABEL" )
[[ "$CTEST_VERBOSE" -eq 1 ]]      && CTEST_CMD+=( -V )
[[ "$CTEST_RERUN_FAILED" -eq 1 ]] && CTEST_CMD+=( --rerun-failed )
[[ "$CTEST_STOP_ON_FAILURE" -eq 1 ]] && CTEST_CMD+=( --stop-on-failure )
[[ -n "$CTEST_REPEAT_UNTIL_FAIL" ]] && CTEST_CMD+=( --repeat-until-fail "$CTEST_REPEAT_UNTIL_FAIL" )

echo "Command: ${CTEST_CMD[*]}"
"${CTEST_CMD[@]}"
