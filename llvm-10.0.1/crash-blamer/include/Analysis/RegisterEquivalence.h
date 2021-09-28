//===- RegisterEquivalence.h - Register Equivalence -----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef REGISTER_EQ_H
#define REGISTER_EQ_H

#include "Analysis/TaintAnalysis.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"

#include <unordered_map>
#include <set>

using namespace llvm;
using namespace crash_blamer;

// Class that implements the Register Equivalence Analysis.
class RegisterEquivalence {
  const TargetRegisterInfo *TRI;
  const TargetInstrInfo *TII;

  // Maps a register to registers from the same equivalance set.
  using RegisterEqSet = std::unordered_map<unsigned, std::set<unsigned>>;
  // Maps intr to the current reg info.
  using RegEqInfoPerMI = std::unordered_map<MachineInstr*, RegisterEqSet>;

  RegEqInfoPerMI RegInfo;

  // Maps MBB num into regs.
  std::unordered_map<unsigned, RegisterEqSet> LiveOuts;
public:
  void dumpRegTableAfterMI(MachineInstr* MI);
  void dumpRegTable(RegisterEqSet &Regs);

  void invalidateRegEq(MachineInstr &MI, unsigned Reg);

  void processMI(MachineInstr &MI);
  bool applyRegisterCopy(MachineInstr &MI);
  bool applyLoad(MachineInstr &MI);
  bool applyStore(MachineInstr &MI);
  bool applyCall(MachineInstr &MI);
  bool applyRegDef(MachineInstr &MI);

  // Return true if two regs are equalante at this program point.
  bool isEquvalent(MachineInstr &MI,
                   unsigned Reg1, unsigned Reg2);

  void join(MachineBasicBlock &MBB, RegisterEqSet &LiveIns);
  void registerEqDFAnalysis(MachineFunction &MF);
  void init(MachineFunction &MF);
  bool run(MachineFunction &MF);
  RegisterEquivalence() = default;
};

#endif
