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
using namespace crash_analyzer;

struct RegisterOffsetPair {
  unsigned RegNum;
  int64_t Offset = 0;

  bool IsDeref = false;

  bool operator==(const RegisterOffsetPair &p) const {
    return RegNum == p.RegNum && Offset == p.Offset;
  }

  bool operator<(const RegisterOffsetPair &p) const {
    if (Offset == p.Offset) {
      return RegNum < p.RegNum;
    }
    return Offset < p.Offset;
  }

  RegisterOffsetPair (unsigned reg)
    : RegNum(reg), Offset(0) {}
  RegisterOffsetPair (unsigned reg, int64_t o)
    : RegNum(reg), Offset(o) {}
};

// Class that implements the Register Equivalence Analysis.
class RegisterEquivalence {
  const TargetRegisterInfo *TRI;
  const TargetInstrInfo *TII;

  struct RegisterOffsetPairHash {
    std::size_t operator () (const RegisterOffsetPair &p) const {
        auto h1 = std::hash<unsigned>{}(p.RegNum);
        auto h2 = std::hash<int64_t>{}(p.Offset);
        return h1 ^ h2;
    }
  };

  // Maps a register to registers from the same equivalance set.
  using RegisterEqSet =
    std::unordered_map<RegisterOffsetPair,
                       std::set<RegisterOffsetPair>, RegisterOffsetPairHash>;
  // Maps intr to the current reg info.
  using RegEqInfoPerMI =
      std::unordered_map<MachineInstr*, RegisterEqSet>;

  RegEqInfoPerMI RegInfo;

  // Maps MBB num into regs.
  std::unordered_map<unsigned, RegisterEqSet> LiveOuts;
public:
  void dumpRegTableAfterMI(MachineInstr* MI);
  void dumpRegTable(RegisterEqSet &Regs);

  std::set<RegisterOffsetPair>
    getEqRegsAfterMI(MachineInstr* MI, RegisterOffsetPair Reg);

  void invalidateRegEq(MachineInstr &MI,
                       RegisterOffsetPair Reg);

  void processMI(MachineInstr &MI);
  bool applyRegisterCopy(MachineInstr &MI);
  bool applyLoad(MachineInstr &MI);
  bool applyStore(MachineInstr &MI);
  bool applyCall(MachineInstr &MI);
  bool applyRegDef(MachineInstr &MI);

  // Return true if two regs are equivalent at this program point.
  bool isEquvalent(MachineInstr &MI,
                   RegisterOffsetPair Reg1, RegisterOffsetPair Reg2);

  void join(MachineBasicBlock &MBB, RegisterEqSet &LiveIns);
  void registerEqDFAnalysis(MachineFunction &MF);
  void init(MachineFunction &MF);
  bool run(MachineFunction &MF);
  RegisterEquivalence() = default;
};

#endif
