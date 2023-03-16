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

void RegisterEquivalence::join(MachineBasicBlock &MBB, RegisterEqSet &LiveIns) {
  LLVM_DEBUG(llvm::dbgs() << "** join for bb." << MBB.getNumber() << "\n");

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
    LLVM_DEBUG(llvm::dbgs() << "pred bb." << PredBlock->getNumber() << ":\n");
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

void RegisterEquivalence::dumpRegTableAfterMI(MachineInstr *MI) {
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
      llvm::dbgs() << printReg(eq.RegNum, TRI);
      if (eq.Offset)
        llvm::dbgs() << "+(" << eq.Offset << ")";
      llvm::dbgs() << " ";
    }
    llvm::dbgs() << "}\n";
  }
  llvm::dbgs() << '\n';
}

std::set<RegisterOffsetPair>
RegisterEquivalence::getEqRegsAfterMI(MachineInstr *MI,
                                      RegisterOffsetPair Reg) {
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
      llvm::dbgs() << printReg(eq.RegNum, TRI);
      if (eq.Offset)
        llvm::dbgs() << "+(" << eq.Offset << ")";
      llvm::dbgs() << " ";
    }
    llvm::dbgs() << "}\n";
  }
  llvm::dbgs() << '\n';
}

void RegisterEquivalence::invalidateRegEq(MachineInstr &MI,
                                          RegisterOffsetPair Reg) {
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

void RegisterEquivalence::invalidateAllRegUses(MachineInstr &MI,
                                               RegisterOffsetPair Reg) {
  const MachineFunction *MF = MI.getMF();
  auto TRI = MF->getSubtarget().getRegisterInfo();
  // Firstly, invalidate all equivalences of the Reg.
  invalidateRegEq(MI, Reg);
  if (Reg.IsDeref)
    return;
  auto &Regs = RegInfo[&MI];
  // Then, if the Reg is simple register (ex. $eax):
  // - Invalidate Reg uses as a base register (deref->($eax)+(Offset)).
  // - Invalidate Regs sub/super registers uses as simple registers. (ex. $rax)
  // - Invalidate Regs sub/super registers as base registers. (ex.
  // deref->($rax)+(Offset))
  for (auto &eqs : Regs) {
    if (eqs.first.RegNum && TRI->regsOverlap(eqs.first.RegNum, Reg.RegNum))
      invalidateRegEq(MI, eqs.first);
  }
}

void RegisterEquivalence::setRegEq(MachineInstr &MI, RegisterOffsetPair Src,
                                   RegisterOffsetPair Dest) {
  if (RegInfo[&MI][Dest].find(Src) != RegInfo[&MI][Dest].end())
    return;
  // Set equivalence between Src and Dest.
  RegInfo[&MI][Src].insert(Dest);
  RegInfo[&MI][Dest].insert(Src);
  // Set Src identity equivalence.
  RegInfo[&MI][Src].insert(Src);

  // Set transitive equivalence between Dest and locations equivalent to Src.
  for (auto LL : RegInfo[&MI][Src]) {
    if (LL == Dest || LL == Src)
      continue;
    setRegEq(MI, LL, Dest);
  }
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

  // First invalidate dest reg, since it is being rewritten.
  invalidateAllRegUses(MI, Dest);

  // Set (transitive) equivalence.
  setRegEq(MI, Src, Dest);
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

  // Transform deref->$rip+(off) to deref->$noreg+(rip+off).
  auto CATI = getCATargetInfoInstance();
  std::string RegName = TRI->getRegAsmName(SrcReg).lower();
  if (CATI->isPCRegister(RegName) && CATI->getInstAddr(&MI)) {
    SrcReg = 0;
    SrcOffset += *CATI->getInstAddr(&MI) + *CATI->getInstSize(&MI);
  }

  RegisterOffsetPair Src{SrcReg, SrcOffset};
  Src.IsDeref = true;
  RegisterOffsetPair Dest{DestReg};

  // First invalidate dest reg, since it is being rewritten.
  invalidateAllRegUses(MI, Dest);

  // If SrcReg is redefined (same as DestReg), set only identity equivalence.
  if (Src.RegNum == Dest.RegNum) {
    if (RegInfo[&MI][Dest].find(Src) == RegInfo[&MI][Dest].end())
      RegInfo[&MI][Src].insert(Src);
    return true;
  }

  // Set (transitive) equivalence.
  setRegEq(MI, Src, Dest);
  // dumpRegTableAfterMI(&MI);

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

  // Transform deref->$rip+(off) to deref->$noreg+(rip+off).
  auto CATI = getCATargetInfoInstance();
  std::string RegName = TRI->getRegAsmName(DestReg).lower();
  if (CATI->isPCRegister(RegName) && CATI->getInstAddr(&MI)) {
    DestReg = 0;
    DstOffset += *CATI->getInstAddr(&MI) + *CATI->getInstSize(&MI);
  }

  RegisterOffsetPair Dest{DestReg, DstOffset};
  Dest.IsDeref = true;

  // We are storing a constant.
  if (!srcDest->Source->isReg()) {
    invalidateAllRegUses(MI, Dest);
    return true;
  }

  auto SrcReg = srcDest->Source->getReg();
  RegisterOffsetPair Src{SrcReg};

  // First invalidate dest reg, since it is being rewritten.
  invalidateAllRegUses(MI, Dest);

  // Set (transitive) equivalence.
  setRegEq(MI, Src, Dest);

  return true;
}

bool RegisterEquivalence::applyCall(MachineInstr &MI) {
  // TODO: Implement this by invalidating registers
  // that will be clobbered by the call.
  // From Retracer: Our static forward analysis is
  // an intra-procedural analysis. We
  // do not analyze callee functions in this analysis.
  // Instead, given a call instruction, we invalidate
  // value relations for volatile registers which
  // can be modified by the callee based on the calling
  // convention [44] as well as memory locations. We also update
  // the stack pointer if the callee is responsible for
  // cleaning up the stack under the function’s calling convention.
  return false;
}

bool RegisterEquivalence::applyRegDef(MachineInstr &MI) {
  for (MachineOperand &MO : MI.operands()) {
    if (MO.isReg() && MO.isDef()) {
      RegisterOffsetPair RegDef{MO.getReg()};
      invalidateAllRegUses(MI, RegDef);
    }
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

bool RegisterEquivalence::isEquivalent(MachineInstr &MI,
                                       RegisterOffsetPair Reg1,
                                       RegisterOffsetPair Reg2) {
  if (RegInfo[&MI][Reg1].find(Reg2) == RegInfo[&MI][Reg1].end())
    return false;
  assert(RegInfo[&MI][Reg2].find(Reg1) != RegInfo[&MI][Reg2].end() &&
         "Register Equivalence is symmetric relation");
  // Transitivity should be handled by setRegEq method.
  return true;
}

bool RegisterEquivalence::verifyEquivalenceTransitivity(
    MachineInstr &MI, RegisterOffsetPair Reg1, RegisterOffsetPair Reg2) {
  if (!isEquivalent(MI, Reg1, Reg2))
    return false;

  for (auto T : RegInfo[&MI][Reg2]) {
    if (!isEquivalent(MI, Reg1, T))
      return false;
  }

  return true;
}

bool RegisterEquivalence::verifyOverlapsInvalidation(MachineInstr &MI,
                                                     unsigned RegNum) {
  auto &Regs = RegInfo[&MI];
  for (auto &eqs : Regs) {
    const MachineFunction *MF = MI.getMF();
    auto TRI = MF->getSubtarget().getRegisterInfo();
    if (eqs.first.RegNum && TRI->regsOverlap(eqs.first.RegNum, RegNum))
      if (eqs.second.size() > 1)
        return false;
  }
  return true;
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
