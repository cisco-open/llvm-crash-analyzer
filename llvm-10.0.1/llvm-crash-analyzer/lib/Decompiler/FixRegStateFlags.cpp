//===- FixRegStateFlags.cpp -----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Decompiler/FixRegStateFlags.h"

#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetLowering.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"

using namespace llvm;

#define DEBUG_TYPE "fix-reg-state-flags"

bool crash_analyzer::FixRegStateFlags::run(MachineFunction &MF) {
  // TODO: Add frame-setup for the PUSH64r $rbp and
  // destroy-frame for the $rbp = POP64r.
  const auto &TRI = MF.getSubtarget().getRegisterInfo();

  for (auto &MBB : MF) {
    // TODO: Revisit this logic. We keep tracking of
    // all defined registers, so if we face a register
    // use that isn't defined, we assume the register
    // was line-in (premise: the final generated
    // code was properly generated).
    SmallSet<unsigned, 32> DefinedRegs;
    MachineInstr* Call = nullptr;
    for (auto &MI : MBB) {
      if (MI.isCall())
        Call = &MI;
      for (MachineOperand &MO : MI.operands()) {
        if (MO.isReg() && MO.isDef() && !DefinedRegs.count(MO.getReg())) {
          DefinedRegs.insert(MO.getReg());
        } else if (MO.isReg() && !MO.isImplicit() && MO.isUse()) {
          unsigned Reg = MO.getReg();
          if (!Reg)
            continue;

          // The call maight have defined the register impicitly, e.g. eax/rax
          // for the return value.
          // TODO: Add implicit defs for arguments after calls (e.g. $rdi).
          if (Call && TRI->isCallsRetValReg(Reg)) {
            MachineOperand MOReg =
                MachineOperand::CreateReg(MO.getReg(), true, true);
            Call->addOperand(MOReg);
            continue;
          }
          if (!DefinedRegs.count(MO.getReg()) &&
              !MBB.isLiveIn(MO.getReg()))
            MBB.addLiveIn(MO.getReg());
        }
      }
    }
  }

  return true;
}
