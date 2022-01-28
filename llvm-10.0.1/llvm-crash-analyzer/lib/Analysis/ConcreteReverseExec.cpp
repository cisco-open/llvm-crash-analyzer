//===- ConcreteReverseExec.cpp - Concrete Reverse Execution ---------------===//
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

static cl::opt<bool>
DisableCRE("disable-cre",
           cl::desc("Disable Concrete Reverse Execution."),
           cl::init(false));

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

void ConcreteReverseExec::dump2() {
  llvm::dbgs() << "\n****Concrete Register Values For Function: "
                          << mf->getName() << "\n";
  for (const auto &R
       : currentRegisterValues) {
    if (R.Value != "")
      llvm::dbgs() << R.Name << ": " << R.Value << "\n";
    else
      llvm::dbgs() << R.Name << ": "
                   << "<not available>\n";
  }
}

// TODO: Optimize this.
void ConcreteReverseExec::updateCurrRegVal(std::string Reg, std::string Val) {
  for (auto &R : currentRegisterValues) {
    if (R.Name == Reg) {
      if (Val == "") {
        R.Value = "";
        return;
      }

      // Register value is unknown.
      if (R.Value == "") {
        if (RegAliases.getRegSize(Reg) == 64) {
          const unsigned RegValInBits = (Val.size() - 2) / 2 * 8;
          if (RegValInBits <= 64)
            R.Value = Val;
          else {
            // drop 0x
            Val.erase(Val.begin());
            Val.erase(Val.begin());
            // get last 8 bytes.
            R.Value = "0x" + Val.substr(/*8 bytes*/Val.size() - 16);
          }
        } else if (RegAliases.getRegSize(Reg) == 32) {
          const unsigned RegValInBits = (Val.size() - 2) / 2 * 8;
          if (RegValInBits <= 32)
            R.Value = Val;
          else {
            // drop 0x
            Val.erase(Val.begin());
            Val.erase(Val.begin());
            // get last 4 bytes.
            R.Value = "0x" + Val.substr(/*4 bytes*/Val.size() - 8);
          }
        } else if (RegAliases.getRegSize(Reg) == 16) {
          const unsigned RegValInBits = (Val.size() - 2) / 2 * 8;
          if (RegValInBits <= 16)
            R.Value = Val;
          else {
            // drop 0x
            Val.erase(Val.begin());
            Val.erase(Val.begin());
            // get last 2 bytes.
            R.Value = "0x" + Val.substr(/*2 bytes*/Val.size() - 4);
          }
        }
        return;
      }

      // There is already a value that needs to be updated.
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
  // If the option is enabled, we skip the CRE of the MIs.
  if (DisableCRE)
    return;

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
      LLVM_DEBUG(llvm::dbgs() << MI << " modifies " << RegName << "\n";);
      // Here we update the register values.

      // TODO: Handle all posible opcodes here.
      // For all unsupported MIs, we just invalidates the value in reg
      // by setting it to "".

      // If the value of the register isn't available, we have nothing to
      // update.
      // FIXME: Is this right?
      auto regVal = getCurretValueInReg(RegName);
      if (regVal == "")
        continue;

      // Skip push/pop intructions here.
      if (TII->isPush(MI) || TII->isPop(MI))
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
        updateCurrRegVal(std::get<3>(regTripple), newValue);
        dump();
        continue;
      }
       // FIXME: This isn't right, since current instruction shouldn't
       // be using the new value.
       /*else if (MI.isMoveImmediate()) {
        if (!MI.getOperand(1).isImm()) {
          updateCurrRegVal(RegName, "");
          return;
        }
        Val = MI.getOperand(1).getImm();
        std::stringstream SS;
        SS << std::hex << regVal;
        SS >> Val;
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
        updateCurrRegVal(std::get<3>(regTripple), newValue);
        dump();
        return;
      }*/

      // The MI is not supported, so consider it as not available.
      LLVM_DEBUG(llvm::dbgs()
                << "Concrete Rev Exec not supported for \n";
		MI.dump(););
      auto regAliasesInfo = getRegAliasesInfo();
      auto regInfoId = regAliasesInfo.getID(RegName);
      if (!regInfoId) {
        updateCurrRegVal(RegName, "");
        dump();
        continue;
      }
      auto regTripple = regAliasesInfo.getRegMap(*regInfoId);
      updateCurrRegVal(std::get<0>(regTripple), "");
      updateCurrRegVal(std::get<1>(regTripple), "");
      updateCurrRegVal(std::get<2>(regTripple), "");
      updateCurrRegVal(std::get<3>(regTripple), "");
      dump();
    }
  }
}
