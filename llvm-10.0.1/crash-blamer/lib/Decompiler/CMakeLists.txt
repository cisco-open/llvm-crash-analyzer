include_directories(${LLVM_MAIN_INCLUDE_DIR}/)

set(LLVM_LINK_COMPONENTS
  AsmPrinter
  Object
  Support
  Symbolize
  Target
  )

llvm_add_library(CrashBlamerDecompiler
  Decompiler.cpp
  )
