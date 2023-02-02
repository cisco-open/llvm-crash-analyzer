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

add_llvm_tool(llvm-crash-analyzer-ta
  llvm-crash-analyzer-ta.cpp
  DEPENDS
    intrinsics_gen
  )

target_link_libraries (llvm-crash-analyzer-ta
  PRIVATE
    CrashAnalyzerTaintAnalysis
  )
