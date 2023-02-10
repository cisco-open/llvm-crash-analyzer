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
class ConcreteReverseExec;

namespace llvm {
namespace crash_analyzer {

enum TaintInfoType { ImmediateVal, RegisterLoc, MemoryLoc };

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
  bool IsTaintMemAddr() const { return IsConcreteMemory; }
  uint64_t GetTaintMemAddr() const { return ConcreteMemoryAddress; }
  std::tuple<unsigned, int, int> getTuple() const;

  friend bool operator==(const TaintInfo &T1, const TaintInfo &T2);
  friend bool operator!=(const TaintInfo &T1, const TaintInfo &T2);
  friend bool operator<(const TaintInfo &T1, const TaintInfo &T2);
  friend raw_ostream &operator<<(raw_ostream &os, const TaintInfo &T);
  bool isTargetStartTaint(unsigned CrashOrder) const;
};

class TaintAnalysis {
private:
  StringRef TaintDotFileName;
  StringRef MirDotFileName;
  SmallVector<TaintInfo, 8> TaintList;
  Decompiler *Dec = nullptr;
  // We use this flag to avoid decompilation on demand
  // for calls in the case of llvm-crash-analyzer-ta tool.
  bool isCrashAnalyzerTATool = false;

  // Used to indicate that we faced a non inlined frame.
  unsigned analysisStartedAt = 1;
  bool PrintPotentialCrashCauseLocation = false;
  ConcreteReverseExec *CRE = nullptr;
  RegisterEquivalence *REA = nullptr;

public:
  TaintAnalysis(StringRef TaintDotFileName, StringRef MirDotFileName,
                bool PrintPotentialCrashCauseLocation);
  TaintAnalysis(bool b) : isCrashAnalyzerTATool(b) {}

  bool runOnBlameModule(BlameModule &BM);
  bool runOnBlameMF(BlameModule &BM, const MachineFunction &MF,
                    TaintDataFlowGraph &TaintDFG, bool CalleeNotInBT,
                    unsigned levelOfCalledFn,
                    SmallVector<TaintInfo, 8> *TL_Of_Caller = nullptr,
                    const MachineInstr *CallMI = nullptr);

  void resetTaintList(SmallVectorImpl<TaintInfo> &TL);
  void mergeTaintList(SmallVectorImpl<TaintInfo> &Dest_TL,
                      SmallVectorImpl<TaintInfo> &Src_TL);
  bool handleGlobalVar(TaintInfo &Ti);
  bool propagateTaint(DestSourcePair &DS, SmallVectorImpl<TaintInfo> &TL,
                      const MachineInstr &MI, TaintDataFlowGraph &TaintDFG,
                      RegisterEquivalence &REAnalysis,
                      const MachineInstr *CallMI = nullptr);
  void startTaint(DestSourcePair &DS, SmallVectorImpl<TaintInfo> &TL,
                  const MachineInstr &MI, TaintDataFlowGraph &TaintDFG,
                  RegisterEquivalence &REAnalysis);
  void insertTaint(DestSourcePair &DS, SmallVectorImpl<TaintInfo> &TL,
                   const MachineInstr &MI, TaintDataFlowGraph &TaintDFG,
                   RegisterEquivalence &REAnalysis);
  bool continueAnalysis(const MachineInstr &MI, SmallVectorImpl<TaintInfo> &TL,
                        RegisterEquivalence &REAnalysis);
  void removeFromTaintList(TaintInfo &Op, SmallVectorImpl<TaintInfo> &TL);
  bool addToTaintList(TaintInfo &Ti, SmallVectorImpl<TaintInfo> &TL);
  void printTaintList(SmallVectorImpl<TaintInfo> &TL);
  void printTaintList2(SmallVectorImpl<TaintInfo> &TL);
  void printDestSrcInfo(DestSourcePair &DS, const MachineInstr &MI);
  bool shouldAnalyzeCall(SmallVectorImpl<TaintInfo> &TL);
  TaintInfo isTainted(TaintInfo &Op, SmallVectorImpl<TaintInfo> &TL,
                      RegisterEquivalence *REAnalysis = nullptr,
                      const MachineInstr *MI = nullptr);
  void calculateMemAddr(TaintInfo &Ti);
  MachineFunction *getCalledMF(const BlameModule &BM, std::string Name);
  bool getIsCrashAnalyzerTATool() const;
  void setDecompiler(Decompiler *D);
  Decompiler *getDecompiler() const;
  void setCRE(ConcreteReverseExec *cre);
  ConcreteReverseExec *getCRE() const;
  void setREAnalysis(RegisterEquivalence *rea);
  RegisterEquivalence *getREAnalysis();
};

} // namespace crash_analyzer
} // namespace llvm

#endif
