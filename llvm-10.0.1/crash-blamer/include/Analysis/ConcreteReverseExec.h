//===- ConcreteReverseExec.h - Cncrete Reverse Execution ------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef CRE_
#define CRE_

#include "Analysis/TaintAnalysis.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"

using namespace llvm;
using namespace crash_blamer;

// Class that implements the Cncrete Reverse Execution.
class ConcreteReverseExec {
  // This represents current values in the registers.
  MachineFunction::RegisterCrashInfo currentRegisterValues;
  const MachineFunction *mf;
  // Going backward, remember if the register is defined already.
  llvm::DenseSet<Register> RegistersDefs;

 public:
  // Init the curr reg values with the values from the 'regInfo' attribute,
  // which are the values read from corefile.
  ConcreteReverseExec(const MachineFunction *MF)
      : currentRegisterValues(MF->getCrashRegInfo()), mf(MF) {}
  void dump();
  void updateCurrRegVal(std::string Reg, std::string Val);
  // Reverse execution of the MI by updating the currentRegisterValues.
  void execute(const MachineInstr &MI);
};

#endif
