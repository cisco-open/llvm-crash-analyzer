include_directories(${LLVM_MAIN_INCLUDE_DIR}/)

set(LLVM_LINK_COMPONENTS
  Support
  )

llvm_add_library(CrashBlamerTaintAnalysis
  TaintAnalysis.cpp
  DEPENDS
    intrinsics_gen
  )
