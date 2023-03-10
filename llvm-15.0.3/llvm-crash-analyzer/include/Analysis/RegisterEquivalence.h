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
#include "Target/CATargetInfo.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"

#include <set>
#include <unordered_map>

using namespace llvm;
using namespace crash_analyzer;

struct RegisterOffsetPair {
  unsigned RegNum;
  int64_t Offset = 0;

  bool IsDeref = false;

  bool operator==(const RegisterOffsetPair &p) const {
    return RegNum == p.RegNum && Offset == p.Offset && IsDeref == p.IsDeref;
  }

  bool operator<(const RegisterOffsetPair &p) const {
    if (Offset == p.Offset) {
      if (RegNum == p.RegNum)
        return IsDeref < p.IsDeref;
      return RegNum < p.RegNum;
    }
    return Offset < p.Offset;
  }

  RegisterOffsetPair(unsigned reg) : RegNum(reg), Offset(0) {}
  RegisterOffsetPair(unsigned reg, int64_t o) : RegNum(reg), Offset(o) {}
  RegisterOffsetPair(unsigned reg, int64_t o, bool deref)
      : RegNum(reg), Offset(o), IsDeref(deref) {}
};

// Class that implements the Register Equivalence Analysis.
class RegisterEquivalence {
  const TargetRegisterInfo *TRI;
  const TargetInstrInfo *TII;

  struct RegisterOffsetPairHash {
    std::size_t operator()(const RegisterOffsetPair &p) const {
      auto h1 = std::hash<unsigned>{}(p.RegNum);
      auto h2 = std::hash<int64_t>{}(p.Offset);
      return h1 ^ h2;
    }
  };

  // Maps a register to registers from the same equivalance set.
  using RegisterEqSet =
      std::unordered_map<RegisterOffsetPair, std::set<RegisterOffsetPair>,
                         RegisterOffsetPairHash>;
  // Maps intr to the current reg info.
  using RegEqInfoPerMI = std::unordered_map<MachineInstr *, RegisterEqSet>;

  RegEqInfoPerMI RegInfo;

  // Maps MBB num into regs.
  std::unordered_map<unsigned, RegisterEqSet> LiveOuts;

public:
  void dumpRegTableAfterMI(MachineInstr *MI);
  void dumpRegTable(RegisterEqSet &Regs);

  std::set<RegisterOffsetPair> getEqRegsAfterMI(MachineInstr *MI,
                                                RegisterOffsetPair Reg);

  void invalidateRegEq(MachineInstr &MI, RegisterOffsetPair Reg);

  void invalidateAllRegUses(MachineInstr &MI, RegisterOffsetPair Reg);

  void setRegEq(MachineInstr &MI, RegisterOffsetPair Src,
                RegisterOffsetPair Dest);

  void processMI(MachineInstr &MI);
  bool applyRegisterCopy(MachineInstr &MI);
  bool applyLoad(MachineInstr &MI);
  bool applyStore(MachineInstr &MI);
  bool applyCall(MachineInstr &MI);
  bool applyRegDef(MachineInstr &MI);

  // Return true if two regs are equivalent at this program point.
  bool isEquivalent(MachineInstr &MI, RegisterOffsetPair Reg1,
                    RegisterOffsetPair Reg2);

  // If Reg1 is equivalent to Reg2, verify that Reg1 is equivalent to
  // all regs equivalent to Reg2.
  bool verifyEquivalenceTransitivity(MachineInstr &MI, RegisterOffsetPair Reg1,
                                     RegisterOffsetPair Reg2);

  // If Register is redefined and its equivalances are invalidated,
  // confirm that that is done for all sub/super registers as well.
  bool verifyOverlapsInvalidation(MachineInstr &MI, unsigned RegNum);

  void join(MachineBasicBlock &MBB, RegisterEqSet &LiveIns);
  void registerEqDFAnalysis(MachineFunction &MF);
  void init(MachineFunction &MF);
  bool run(MachineFunction &MF);
  RegisterEquivalence() = default;
};

#endif
