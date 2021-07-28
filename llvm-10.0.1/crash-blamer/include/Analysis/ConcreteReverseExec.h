//===- ConcreteReverseExec.h - Concrete Reverse Execution -----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef CRE_
#define CRE_

#include "Analysis/TaintAnalysis.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"

#include <unordered_map>
#include <tuple>

using namespace llvm;
using namespace crash_blamer;

using RegAliasTripple = std::tuple<std::string, std::string, std::string>;

// TODO: This should be Target independent, so move it
// to llvm/Target/x86 part.
struct RegisterMappings {
  // This will be mapped into register aliases.
  // e.g. rax, eax, ax will hold a same id.
  std::unordered_map<unsigned, RegAliasTripple> regMap;
public:
  RegisterMappings() {
    regMap[0] = std::make_tuple("rax", "eax", "ax");
    // TODO: add for all other regs.
  }

  Optional<unsigned> getID(std::string reg) const {
    if (reg == "rax" || reg == "eax" || reg == "ax")
      return 0;
    // TODO: Handle all regs.
    return None;
  }

  RegAliasTripple& getRegMap(unsigned id) const {
    return const_cast<RegAliasTripple&>(regMap.at(id));
  }
};

// Class that implements the Concrete Reverse Execution.
class ConcreteReverseExec {
  // This represents current values in the registers.
  MachineFunction::RegisterCrashInfo currentRegisterValues;
  const MachineFunction *mf;
  // Going backward, remember if the register is defined already.
  llvm::DenseSet<Register> RegistersDefs;

  RegisterMappings RegAliases;

 public:
  // Init the curr reg values with the values from the 'regInfo' attribute,
  // which are the values read from corefile.
  ConcreteReverseExec(const MachineFunction *MF)
      : currentRegisterValues(MF->getCrashRegInfo()), mf(MF) {
    RegAliases =  RegisterMappings();
  }
  void dump();
  void updateCurrRegVal(std::string Reg, std::string Val);
  std::string getCurretValueInReg(const std::string &Reg);

  RegisterMappings& getRegAliasesInfo() {
    return RegAliases;
  }

  // Reverse execution of the MI by updating the currentRegisterValues.
  void execute(const MachineInstr &MI);
};

#endif
