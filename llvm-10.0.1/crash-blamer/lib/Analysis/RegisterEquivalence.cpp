//===- RegisterEquivalence.cpp - Register Equivalence ---------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/RegisterEquivalence.h"

#include "llvm/ADT/PostOrderIterator.h"

#include <algorithm>

#define DEBUG_TYPE "register-eq"

void RegisterEquivalence::init(MachineFunction &MF) {
  TRI = MF.getSubtarget().getRegisterInfo();
  TII = MF.getSubtarget().getInstrInfo();
}

void RegisterEquivalence::join(MachineBasicBlock &MBB,
    RegisterEqSet &LiveIns) {
  LLVM_DEBUG(llvm::dbgs() << "** join for bb."
                          << MBB.getNumber() << "\n");

  // This is entry BB.
  if (MBB.getNumber() == 0) {
    for (const MachineBasicBlock::RegisterMaskPair &LI : MBB.liveins()) {
      LiveIns[LI.PhysReg].insert(LI.PhysReg);
    }
    return;
  }

  SmallVector<MachineBasicBlock *, 8> Predecessors(MBB.pred_begin(),
                                              MBB.pred_end());
  for (auto *PredBlock : Predecessors) {
    LLVM_DEBUG(llvm::dbgs() << "pred bb."
                            << PredBlock->getNumber() << ":\n");
    LLVM_DEBUG(dumpRegTable(LiveOuts[PredBlock->getNumber()]));
    for (auto &regs : LiveOuts[PredBlock->getNumber()]) {
      unsigned reg = regs.first;
      std::set_union(LiveIns[reg].begin(), LiveIns[reg].end(),
                LiveOuts[PredBlock->getNumber()][reg].begin(),
                LiveOuts[PredBlock->getNumber()][reg].end(),
                std::inserter(LiveIns[reg], LiveIns[reg].begin()));
    }
  }
}

void RegisterEquivalence::dumpRegTableAfterMI(MachineInstr* MI) {
  llvm::dbgs() << "Reg Eq Table after: " << *MI;
  auto &Regs = RegInfo[MI];
  for (auto &e : Regs) {
    llvm::dbgs() << printReg(e.first, TRI) << " : { ";
    for (auto &eq : e.second) {
      llvm::dbgs() <<  printReg(eq, TRI) << " ";
    }
    llvm::dbgs() << "}\n";
  }
  llvm::dbgs() << '\n';
}

void RegisterEquivalence::dumpRegTable(RegisterEqSet &Regs) {
  llvm::dbgs() << "Reg Eq Table:\n";
  for (auto &e : Regs) {
    llvm::dbgs() << printReg(e.first, TRI) << " : { ";
    for (auto &eq : e.second) {
      llvm::dbgs() <<  printReg(eq, TRI) << " ";
    }
    llvm::dbgs() << "}\n";
  }
  llvm::dbgs() << '\n';
}

void RegisterEquivalence::invalidateRegEq(
  MachineInstr &MI, unsigned Reg) {
  // Remove this reg from all other eq sets.
  auto &Regs = RegInfo[&MI];
  for (auto &eqs : Regs) {
    // Skip itself.
    if (eqs.first == Reg)
      continue;

    eqs.second.erase(Reg);
  }

  RegInfo[&MI][Reg].clear();
  // Insert identity -- reg is eq to itself only.
  RegInfo[&MI][Reg].insert(Reg);
}

bool RegisterEquivalence::applyRegisterCopy(MachineInstr &MI) {
  auto DestSrc = TII->isCopyInstr(MI);
  if (!DestSrc)
    return false;

  const MachineOperand *DestRegOp = DestSrc->Destination;
  const MachineOperand *SrcRegOp = DestSrc->Source;

  Register SrcReg = SrcRegOp->getReg();
  Register DestReg = DestRegOp->getReg();

  // Ignore identity copies. Yep, these make it as far as LiveDebugValues.
  if (SrcReg == DestReg)
    return false;

  invalidateRegEq(MI, DestReg);

  RegInfo[&MI][SrcReg].insert(DestReg);
  RegInfo[&MI][DestReg].insert(SrcReg);
  RegInfo[&MI][SrcReg].insert(SrcReg);

  return true;
}

bool RegisterEquivalence::applyLoad(MachineInstr &MI) {
  if (!TII->isLoad(MI))
    return false;

  auto srcDest = TII->getDestAndSrc(MI);
  if (!srcDest)
    return false;

  auto SrcReg = srcDest->Source->getReg();
  auto DstReg = srcDest->Destination->getReg();

  // TODO: Take the offset into account.

  //MI.dump();

  // First invalidate dest reg, since it is being rewritten.
  invalidateRegEq(MI, DstReg);

  RegInfo[&MI][SrcReg].insert(DstReg);
  RegInfo[&MI][DstReg].insert(SrcReg);
  RegInfo[&MI][SrcReg].insert(SrcReg);

  return true;
}

bool RegisterEquivalence::applyStore(MachineInstr &MI) {
  if (!TII->isStore(MI))
    return false;

  // TODO: Handle this.
  return false;
}

bool RegisterEquivalence::applyCall(MachineInstr &MI) {
  // TODO: Implement this.
  return false;
}

bool RegisterEquivalence::applyRegDef(MachineInstr &MI) {
  for (MachineOperand &MO : MI.operands()) {
    if (MO.isReg() && MO.isDef())
      invalidateRegEq(MI, MO.getReg());
  }
  return true;
}

void RegisterEquivalence::processMI(MachineInstr &MI) {
  if (applyRegisterCopy(MI))
    return;
  if (applyLoad(MI))
    return;
  if (applyStore(MI))
    return;
  if (applyCall(MI))
    return;
  if (applyRegDef(MI))
    return;
}

void RegisterEquivalence::registerEqDFAnalysis(MachineFunction &MF) {
  ReversePostOrderTraversal<MachineFunction *> RPOT(&MF);
  for (auto *MBB : RPOT) {
    RegisterEqSet LiveIns;
    join(*MBB, LiveIns);
    RegisterEqSet PrevRegSet;
    for (auto &MI : *MBB) {
      if (&MI == &*MBB->begin()) {
        PrevRegSet = LiveIns;
        LLVM_DEBUG(dumpRegTable(LiveIns));
      } else {
        RegInfo[&MI] = PrevRegSet;
      }

      // Process different types of MIs.
      processMI(MI);

      // Handle inst impact onto reg table.
      PrevRegSet = RegInfo[&MI];
      LLVM_DEBUG(dumpRegTableAfterMI(&MI));
    }
    LiveOuts[MBB->getNumber()] = LiveIns;
  }
}

bool RegisterEquivalence::isEquvalent(MachineInstr &MI,
    unsigned Reg1, unsigned Reg2) {
  if (RegInfo[&MI][Reg1].find(Reg2) != RegInfo[&MI][Reg1].end())
    return true;

  // TODO: Check if it is implicitly equalalent?
  // reg0 : {reg1,...} -> reg1 : {reg2,...} ==> reg0 is eq to reg2.

  return false;
}

bool RegisterEquivalence::run(MachineFunction &MF) {
  LLVM_DEBUG(llvm::dbgs() << "*** Register Equivalence Analysis ("
                          << MF.getName() << ")***\n";);

  // 1. Perform data flow analysis - join() (or the merge step).
  // 2. Populate the eq table for the basic block for each program point.
  registerEqDFAnalysis(MF);

  LLVM_DEBUG(llvm::dbgs() << "\n\n";);
  return true;
}
