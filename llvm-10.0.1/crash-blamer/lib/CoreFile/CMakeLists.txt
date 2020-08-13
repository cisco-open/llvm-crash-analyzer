include_directories(${LLVM_MAIN_INCLUDE_DIR}/
                    ${LLVM_MAIN_INCLUDE_DIR}/../../lldb/include/)

set(LLVM_LINK_COMPONENTS
  AsmPrinter
  Object
  Support
  Target
  )

llvm_add_library(CrashBlamerCoreFile
  CoreFile.cpp
  LINK_LIBS
    liblldb
  )
