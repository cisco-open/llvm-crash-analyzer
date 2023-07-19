include_directories(${LLVM_MAIN_INCLUDE_DIR}/
                    ${LLVM_MAIN_INCLUDE_DIR}/../../lldb/include/)

set(LLVM_LINK_COMPONENTS
  AllTargetsCodeGens
  AllTargetsDisassemblers
  AllTargetsDescs
  AllTargetsInfos
  AllTargetsAsmParsers
  CodeGen
  MIRParser
  Object
  Support
  Target
  )

add_crash_balmer_unittest(CRASHANALYZERAnalysisTests
  ConcreteReverseExec.cpp
  RegisterEquivalence.cpp
  TaintInfo.cpp
  MemoryWrapper.cpp
  DEPENDS
    intrinsics_gen
)

target_link_libraries(CRASHANALYZERAnalysisTests
  PRIVATE CrashAnalyzerTaintAnalysis)
