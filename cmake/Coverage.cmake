# LLVM source-based coverage flags for Clang/GCC toolchains.
IF(NOT ENABLE_COVERAGE)
    RETURN()
ENDIF()

IF(MSVC)
    MESSAGE(FATAL_ERROR "ENABLE_COVERAGE is not supported with MSVC.")
ENDIF()

SET(_PPP_COVERAGE_FLAGS "-fprofile-instr-generate -fcoverage-mapping")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_PPP_COVERAGE_FLAGS}")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${_PPP_COVERAGE_FLAGS}")
SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-instr-generate")
SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fprofile-instr-generate")
