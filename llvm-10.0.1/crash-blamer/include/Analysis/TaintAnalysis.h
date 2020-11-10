//===- TaintAnalysis.h - Catch the source of a crash ----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

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

namespace llvm {
namespace crash_blamer {

// Tainted Operands in a Machine Instruction.
// This is a Reg-Offset pair.
// TODO: Take into account:
//   1) Register as offset
//   2) Scaled Index addressing mode
struct TaintInfo {
  const MachineOperand *Op;

  // For mem operands, we rather choose to taint
  // real/concrete addresses (by calculating base_reg + off).
  int64_t Offset;
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
};

class TaintAnalysis {
private:
  SmallVector<TaintInfo, 8> TaintList;
public:

  TaintAnalysis();

  bool runOnBlameModule(const BlameModule &BM);
  bool runOnBlameMF(const MachineFunction &MF);

  bool propagateTaint(DestSourcePair &DS);
  void startTaint(DestSourcePair &DS);
  void removeFromTaintList(TaintInfo &Op);
  void addToTaintList(TaintInfo &Ti);
  void printTaintList();
  void printDestSrcInfo(DestSourcePair &DS);
  TaintInfo isTainted(TaintInfo &Op);
  void calculateMemAddr(TaintInfo &Ti);
};

} // end crash_blamer namespace
} // end llvm namespace
