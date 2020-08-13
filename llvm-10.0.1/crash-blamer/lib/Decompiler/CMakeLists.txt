include_directories(${LLVM_MAIN_INCLUDE_DIR}/)

set(LLVM_LINK_COMPONENTS
  AsmPrinter
  Object
  Support
  Target
  )

llvm_add_library(CrashBlamerDecompiler
  Decompiler.cpp
  )
