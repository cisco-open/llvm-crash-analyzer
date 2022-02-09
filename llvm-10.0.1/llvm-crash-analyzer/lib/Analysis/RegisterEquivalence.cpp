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
      RegisterOffsetPair reg{LI.PhysReg};
      LiveIns[reg].insert(reg);
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
      RegisterOffsetPair reg{regs.first.RegNum};
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
    if (e.first.IsDeref)
      llvm::dbgs() << "deref->";
    llvm::dbgs() << printReg(e.first.RegNum, TRI);
    if (e.first.Offset)
      llvm::dbgs() << "+(" << e.first.Offset << ")";
    llvm::dbgs() << " : { ";
    for (auto &eq : e.second) {
      if (eq.IsDeref)
        llvm::dbgs() << "deref->";
      llvm::dbgs() <<  printReg(eq.RegNum, TRI);
      if (eq.Offset)
        llvm::dbgs() << "+(" << eq.Offset << ")";
      llvm::dbgs() << " ";
    }
    llvm::dbgs() << "}\n";
  }
  llvm::dbgs() << '\n';
}

std::set<RegisterOffsetPair>
RegisterEquivalence::getEqRegsAfterMI(MachineInstr* MI, RegisterOffsetPair Reg) {
  if (RegInfo.size() == 0)
    return {};

  if (RegInfo.find(MI) == RegInfo.end())
    return {};

  auto &Regs = RegInfo[MI];
  if (Regs.find(Reg) == Regs.end())
    return {};
  return Regs[Reg];
}

void RegisterEquivalence::dumpRegTable(RegisterEqSet &Regs) {
  llvm::dbgs() << "Reg Eq Table:\n";
  for (auto &e : Regs) {
    if (e.first.IsDeref)
      llvm::dbgs() << "deref->";
    llvm::dbgs() << printReg(e.first.RegNum, TRI);
    if (e.first.Offset)
      llvm::dbgs() << "+(" << e.first.Offset << ")";
    llvm::dbgs() << " : { ";
    for (auto &eq : e.second) {
      if (eq.IsDeref)
        llvm::dbgs() << "deref->";
      llvm::dbgs() <<  printReg(eq.RegNum, TRI);
      if (eq.Offset)
        llvm::dbgs() << "+(" << eq.Offset << ")";
      llvm::dbgs() << " ";
    }
    llvm::dbgs() << "}\n";
  }
  llvm::dbgs() << '\n';
}

void RegisterEquivalence::invalidateRegEq(
  MachineInstr &MI, RegisterOffsetPair Reg) {
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

  RegisterOffsetPair Src{SrcReg};
  RegisterOffsetPair Dest{DestReg};

  invalidateRegEq(MI, Dest);

  RegInfo[&MI][Src].insert(Dest);
  RegInfo[&MI][Dest].insert(Src);
  RegInfo[&MI][Src].insert(Src);

  return true;
}

bool RegisterEquivalence::applyLoad(MachineInstr &MI) {
  if (!TII->isLoad(MI))
    return false;

  auto srcDest = TII->getDestAndSrc(MI);
  if (!srcDest)
    return false;

  auto SrcReg = srcDest->Source->getReg();
  auto DestReg = srcDest->Destination->getReg();

  int64_t SrcOffset = 0;

  // Take the offset into account.
  if (srcDest->SrcOffset)
    SrcOffset = *srcDest->SrcOffset;

  RegisterOffsetPair Src{SrcReg, SrcOffset};
  Src.IsDeref = true;
  RegisterOffsetPair Dest{DestReg};

  // First invalidate dest reg, since it is being rewritten.
  invalidateRegEq(MI, Dest);

  RegInfo[&MI][Src].insert(Dest);
  RegInfo[&MI][Dest].insert(Src);
  RegInfo[&MI][Src].insert(Src);

  //dumpRegTableAfterMI(&MI);

  return true;
}

bool RegisterEquivalence::applyStore(MachineInstr &MI) {
  if (!TII->isStore(MI))
    return false;

  auto srcDest = TII->getDestAndSrc(MI);
  if (!srcDest)
    return false;

  auto DestReg = srcDest->Destination->getReg();
  int64_t DstOffset = 0;

  // Take the offset into account.
  if (srcDest->DestOffset)
    DstOffset = *srcDest->DestOffset;

  RegisterOffsetPair Dest{DestReg, DstOffset};
  Dest.IsDeref = true;

  // We are storing a constant.
  if (!srcDest->Source->isReg()) {
    invalidateRegEq(MI, Dest);
    return true;
  }

  auto SrcReg = srcDest->Source->getReg();
  RegisterOffsetPair Src{SrcReg};

  // First invalidate dest reg, since it is being rewritten.
  invalidateRegEq(MI, Dest);

  RegInfo[&MI][Src].insert(Dest);
  RegInfo[&MI][Dest].insert(Src);
  RegInfo[&MI][Src].insert(Src);

  return true;
}

bool RegisterEquivalence::applyCall(MachineInstr &MI) {
  // TODO: Implement this.
  return false;
}

bool RegisterEquivalence::applyRegDef(MachineInstr &MI) {
  for (MachineOperand &MO : MI.operands()) {
    if (MO.isReg() && MO.isDef()) {
      RegisterOffsetPair reg{MO.getReg()};
      invalidateRegEq(MI, reg);
    }
  }
  return true;
}

// FIXME: Provide info whether we need to deref something
// at memory address or not.
// E.g.: $rax {$rbp-8} Does it mean value at $rbp-8, or address
// itself?
// TODO: Introduce a special symbol to indicate deref.
// e.g. $rax {[$rbp-8]} or $rax {*$rbp-8}
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

bool RegisterEquivalence::isEquivalent(MachineInstr &MI,
    RegisterOffsetPair Reg1, RegisterOffsetPair Reg2) {
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
