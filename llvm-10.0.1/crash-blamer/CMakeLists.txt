set(CRASH_BLAMER_MAIN_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}) # --src-root
set(CRASH_BLAMER_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/include ) # --includedir
set(CRASH_BLAMER_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(CRASH_BLAMER_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR})

include_directories(include/
                    ${LLVM_MAIN_INCLUDE_DIR}/)

add_subdirectory(lib)
add_subdirectory(test)
add_subdirectory(unittests)

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

add_llvm_tool(crash-blamer
  crash-blamer.cpp
  )

target_link_libraries (crash-blamer
  PRIVATE
    CrashBlamerDecompiler
    CrashBlamerCoreFile
  )
