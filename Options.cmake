# Default to building tests when in CI mode and `CP_BUILD_TESTS` is not explicitly defined.
set(_cp_build_tests_default OFF)
if(NOT DEFINED CP_BUILD_TESTS AND DEFINED ENV{CI} AND "$ENV{CI}" STREQUAL "true")
  set(_cp_build_tests_default ON)
endif()

option(CP_BUILD_TESTS "Build tests. Defaults to OFF, unless the 'CI' environment variable is set to '1'" ${_cp_build_tests_default})

option(CP_RETAIN_X_VALUES "Retain X values for testing." OFF)

option(CP_ENABLE_LIBPOS2_ONLY "Enable libpos2 and disable all executable targets." OFF)
option(CP_ENABLE_LIBPOS2      "Enable libpos2 library target." OFF)

if (CP_ENABLE_LIBPOS2_ONLY)
    set(CP_ENABLE_LIBPOS2 ON)
endif()

# Check first if these were specified in the command line,
# so that we can explicitly enable them even if CP_ENABLE_LIBPOS2_ONLY was specified
macro(cp_target_option OPT HELP)
  string(TOLOWER "${OPT}" _cp_opt_lower)
  set(_cp_${_cp_opt_lower}_default ON)

  # Disable by default if libpos2 only was specified
  if (CP_ENABLE_LIBPOS2_ONLY)
    set(_cp_${_cp_opt_lower}_default OFF)
  endif()

  # If explicitly set, then enable it
  if (CACHE{${OPT}})
    set(_cp_${_cp_opt_lower}_default ON)
  endif()

  option(${OPT} "${HELP}" ${_cp_${_cp_opt_lower}_default})
endmacro()


cp_target_option(CP_ENABLE_PLOTTER      "Enable plotter target.")
cp_target_option(CP_ENABLE_SOLVER       "Enable solver target.")
cp_target_option(CP_ENABLE_PROVER       "Enable prover target.")
cp_target_option(CP_ENABLE_ANALYTICS    "Enable analytics target.")
