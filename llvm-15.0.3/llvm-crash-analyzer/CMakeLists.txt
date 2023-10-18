set(CRASH_ANALYZER_MAIN_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}) # --src-root
set(CRASH_ANALYZER_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/include ) # --includedir
set(CRASH_ANALYZER_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(CRASH_ANALYZER_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR})
option(LLDB_SERVER_GDB_TEST_PATH "Path to GDB for testing" "")

include_directories(include/
                    ${LLVM_MAIN_INCLUDE_DIR}/
                    ${LLVM_MAIN_INCLUDE_DIR}/../../lldb/include/)

add_subdirectory(lib)
add_subdirectory(test)
add_subdirectory(tools)
add_subdirectory(unittests)

if(LLDB_SERVER_GDB_TEST_PATH)
  add_definitions(-DLLDB_SERVER_GDB_TEST_PATH="${LLDB_SERVER_GDB_TEST_PATH}")
endif()

set(LLVM_LINK_COMPONENTS
  AllTargetsCodeGens
  AllTargetsDisassemblers
  AllTargetsDescs
  AllTargetsInfos
  AllTargetsAsmParsers
  Object
  Support
  Target
  )

add_llvm_tool(llvm-crash-analyzer
  llvm-crash-analyzer.cpp
  )

target_link_libraries (llvm-crash-analyzer
  PRIVATE
    liblldb
    CrashAnalyzerDecompiler
    CrashAnalyzerCoreFile
    CrashAnalyzerTaintAnalysis
    CrashAnalyzerTarget
  )
