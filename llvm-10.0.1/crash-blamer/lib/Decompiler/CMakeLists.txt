include_directories(${LLVM_MAIN_INCLUDE_DIR}/
                    ${LLVM_MAIN_INCLUDE_DIR}/../../lldb/include/
                     ${LLVM_MAIN_INCLUDE_DIR}/../../lldb/source/)

set(LLVM_LINK_COMPONENTS
  AsmPrinter
  Support
  Target
  )

llvm_add_library(CrashBlamerDecompiler
  Decompiler.cpp
  FixRegStateFlags.cpp
  LINK_LIBS
    lldbPluginDisassemblerLLVM
  )
