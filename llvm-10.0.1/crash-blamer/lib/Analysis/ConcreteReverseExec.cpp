//===- ConcreteReverseExec.cpp - Cncrete Reverse Execution ----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/ConcreteReverseExec.h"

#include <set>
#include <sstream>
#include <iomanip>

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
      if (R.Value.size() == Val.size())
        R.Value = Val;
      else if (R.Value.size() > Val.size()){
        // drop 0x part.
        Val.erase(Val.begin());
        Val.erase(Val.begin());
        unsigned diff = R.Value.size() - Val.size();
        R.Value.replace(diff, Val.size(), Val);
      } else {
        // Val.size > R.Value.size
        // get the last N chars only:
        //  eax = 0x00000009
        //  ax = 0x0009
        Val.erase(Val.begin());
        Val.erase(Val.begin());
        unsigned diff = Val.size() - R.Value.size() + 2;
        R.Value = "0x" + Val.substr(diff);
      }
      return;
    }
  }
}
std::string
ConcreteReverseExec::getCurretValueInReg(const std::string &Reg) {
  for (auto &R : currentRegisterValues) {
    if (R.Name == Reg)
      return R.Value;
  }
  return std::string("");
}

template< typename T >
std::string intToHex(T num, unsigned regValSize)
{
  std::stringstream stream;
  stream << "0x"
         << std::setfill ('0') << std::setw(regValSize)
         << std::hex << num;
  return stream.str();
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

      // If the value of the register isn't available, we have nothing to
      // update.
      auto regVal = getCurretValueInReg(RegName);
      if (regVal == "")
        continue;

      // Skip push/pop intructions here.
      if (TII->isPushPop(MI))
        continue;

      uint64_t Val = 0;
      std::stringstream SS;
      SS << std::hex << regVal;
      SS >> Val;

      // In c_test_cases/test3.c there is a case
      //  $eax = ADD32ri8 $eax(tied-def 0), 1
      // so handle it.
      if (auto RegImm = TII->isAddImmediate(MI, Reg)) {
        // We do the oposite operation, since we are
        // intereting the instruction going backward.
        Val -= RegImm->Imm;
        // We should update all reg aliases as well.
        // TODO: Improve this.
        auto regAliasesInfo = getRegAliasesInfo();
        auto regInfoId = regAliasesInfo.getID(RegName);
        if (!regInfoId) {
          updateCurrRegVal(RegName, "");
          continue;
        }
        auto regTripple = regAliasesInfo.getRegMap(*regInfoId);
        //regVal.size() - 2 for 0x chars.
        std::string newValue = intToHex(Val, regVal.size() - 2);
        // update reg aliases as well.
        // e.g. if $eax is modified, update both $rax and $ax as well.
        updateCurrRegVal(std::get<0>(regTripple), newValue);
        updateCurrRegVal(std::get<1>(regTripple), newValue);
        updateCurrRegVal(std::get<2>(regTripple), newValue);
        dump();
        continue;
      }

      // The MI is not supported, so consider it as not available.
      updateCurrRegVal(RegName, "");
    }
  }
}
