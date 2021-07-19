//===- ConcreteReverseExec.cpp - Cncrete Reverse Execution ----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/ConcreteReverseExec.h"

#include <set>

#define DEBUG_TYPE "conrecete-rev-exec"

void ConcreteReverseExec::dump() {
  LLVM_DEBUG(llvm::dbgs() << "\n****Concrete Register Values For Function: "
                          << mf->getName() << "\n";
             for (const auto &R
                  : currentRegisterValues) {
               if (R.Value != "")
                 llvm::dbgs() << R.Name << ": " << R.Value << "\n";
               else
                 llvm::dbgs() << R.Name << ": "
                              << "<not available>\n";
             });
}
// TODO: Optimize this.
void ConcreteReverseExec::updateCurrRegVal(std::string Reg, std::string Val) {
  for (auto &R : currentRegisterValues) {
    if (R.Name == Reg) {
      R.Value = Val;
      return;
    }
  }
}

void ConcreteReverseExec::execute(const MachineInstr &MI) {
  // If this instruction modifies any of the registers,
  // update the register values for the function. First definition of the reg
  // is the one that is in the 'regInfo:' (going backward is the first, but it
  // is the latest def actually by going forward).
  auto TRI = MI.getParent()->getParent()->getSubtarget().getRegisterInfo();
  auto TII = MI.getParent()->getParent()->getSubtarget().getInstrInfo();
  // This will be used to avoid implicit operands that can be in the instruction
  // multiple times.
  std::multiset<Register> RegisterWorkList;

  for (const MachineOperand &MO : MI.operands()) {
    if (!MO.isReg()) continue;
    Register Reg = MO.getReg();
    RegisterWorkList.insert(Reg);
    std::string RegName = TRI->getRegAsmName(Reg).lower();
    if (RegisterWorkList.count(Reg) == 1 && MI.modifiesRegister(Reg, TRI)) {
      // If this is the first reg def going backward, remember it.
      if (!RegistersDefs.count(Reg)) {
        RegistersDefs.insert(Reg);
        LLVM_DEBUG(llvm::dbgs() << MI << " modifies(defines val from corefile) "
                                << RegName << "\n";);
        continue;
      }
      LLVM_DEBUG(llvm::dbgs() << MI << " modifies " << RegName << "\n";);
      // Here we update the register values.

      // TODO: Handle all posible opcodes here.
      // For all unsupported MIs, we just invalidates the value in reg
      // by setting it to "".

      // The MI is not supported, so consider it as not available.
      updateCurrRegVal(RegName, "");
    }
  }
}
