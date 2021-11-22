//===- TaintAnalysis.h - Catch the source of a crash ----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef TAINTANALYSIS_
#define TAINTANALYSIS_

#include "Decompiler/Decompiler.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/IR/Module.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

struct Node;
class TaintDataFlowGraph;
class RegisterEquivalence;

namespace llvm {
namespace crash_analyzer {

// Tainted Operands in a Machine Instruction.
// This is a Reg-Offset pair.
// TODO: Take into account:
//   1) Register as offset
//   2) Scaled Index addressing mode
struct TaintInfo {
  const MachineOperand *Op;

  // For mem operands, we rather choose to taint
  // real/concrete addresses (by calculating base_reg + off).
  Optional<int64_t> Offset;
  uint64_t ConcreteMemoryAddress = 0x0;
  bool IsConcreteMemory = false;
  bool IsTaintMemAddr() const {
    return IsConcreteMemory;
  }
  uint64_t GetTaintMemAddr() const {
    return ConcreteMemoryAddress;
  }

  friend bool operator==(const TaintInfo &T1, const TaintInfo &T2);
  friend bool operator!=(const TaintInfo &T1, const TaintInfo &T2);
  friend bool operator<(const TaintInfo &T1, const TaintInfo &T2);
};

class TaintAnalysis {
private:
  StringRef DotFileName = "";
  SmallVector<TaintInfo, 8> TaintList;
  Decompiler *Dec = nullptr;
  // We use this flag to avoid decompilation on demand
  // for calls in the case of llvm-crash-analyzer-ta tool.
  bool isCrashAnalyzerTATool = false;

  // Used to indicate that we faced a non inlined frame.
  unsigned analysisStartedAt = 1;
public:

  TaintAnalysis(StringRef DotFileName);
  TaintAnalysis(bool b) : isCrashAnalyzerTATool(b) {}

  bool runOnBlameModule(const BlameModule &BM);
  bool runOnBlameMF(const BlameModule &BM, const MachineFunction &MF,
	TaintDataFlowGraph &TaintDFG, bool CalleeNotInBT,
    unsigned levelOfCalledFn,
    SmallVector<TaintInfo, 8> *TL_Of_Caller = nullptr,
    const MachineInstr* CallMI = nullptr);

  void resetTaintList(SmallVectorImpl<TaintInfo> &TL);
  void mergeTaintList(SmallVectorImpl<TaintInfo> &Dest_TL, SmallVectorImpl<TaintInfo> &Src_TL);
  bool propagateTaint(DestSourcePair &DS, SmallVectorImpl<TaintInfo> &TL,
                      const MachineInstr &MI, TaintDataFlowGraph &TaintDFG,
                      RegisterEquivalence &REAnalysis,
                      const MachineInstr* CallMI = nullptr);
  void startTaint(DestSourcePair &DS, SmallVectorImpl<TaintInfo> &TL,
                  const MachineInstr &MI, TaintDataFlowGraph &TaintDFG,
                  RegisterEquivalence &REAnalysis);
  void removeFromTaintList(TaintInfo &Op, SmallVectorImpl<TaintInfo> &TL);
  bool addToTaintList(TaintInfo &Ti, SmallVectorImpl<TaintInfo> &TL);
  void printTaintList(SmallVectorImpl<TaintInfo> &TL);
  void printTaintList2(SmallVectorImpl<TaintInfo> &TL);
  void printDestSrcInfo(DestSourcePair &DS);
  bool shouldAnalyzeCall(SmallVectorImpl<TaintInfo> &TL);
  TaintInfo isTainted(TaintInfo &Op, SmallVectorImpl<TaintInfo> &TL,
                      RegisterEquivalence *REAnalysis = nullptr,
                      const MachineInstr *MI = nullptr);
  void calculateMemAddr(TaintInfo &Ti);
  MachineFunction *getCalledMF(const BlameModule &BM, std::string Name);
  bool getIsCrashAnalyzerTATool() const;
  void setDecompiler(Decompiler *D);
  Decompiler *getDecompiler() const;
};

} // end crash_analyzer namespace
} // end llvm namespace

#endif
