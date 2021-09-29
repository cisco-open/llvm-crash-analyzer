include_directories(${LLVM_MAIN_INCLUDE_DIR}/
                    ${LLVM_MAIN_INCLUDE_DIR}/../../lldb/include/)

set(LLVM_LINK_COMPONENTS
  Support
  )

llvm_add_library(CrashBlamerTaintAnalysis
  ConcreteReverseExec.cpp
  RegisterEquivalence.cpp
  TaintAnalysis.cpp
  TaintDataFlowGraph.cpp
  DEPENDS
    intrinsics_gen
  )
