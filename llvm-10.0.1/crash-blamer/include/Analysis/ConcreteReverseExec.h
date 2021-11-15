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
    regMap[1] = std::make_tuple("rdi", "edi", "di");
    regMap[2] = std::make_tuple("rsi", "esi", "si");
    regMap[3] = std::make_tuple("rdx", "edx", "dx");
    regMap[4] = std::make_tuple("rcx", "ecx", "cx");
    regMap[5] = std::make_tuple("r8", "r8d", "r8w");
    regMap[6] = std::make_tuple("r9", "r9d", "r9w");
    regMap[7] = std::make_tuple("r10", "r10d", "r10w");
    regMap[8] = std::make_tuple("r11", "r11d", "r11w");
    regMap[9] = std::make_tuple("rsp", "esp", "sp");
    regMap[10] = std::make_tuple("rbx", "ebx", "bx");
    regMap[11] = std::make_tuple("rbp", "ebp", "bp");
    regMap[12] = std::make_tuple("r12", "r12d", "r12w");
    regMap[13] = std::make_tuple("r13", "r13d", "r13w");
    regMap[14] = std::make_tuple("r14", "r14d", "r14w");
    regMap[15] = std::make_tuple("r15", "r15d", "r15w");
    regMap[16] = std::make_tuple("rip", "rip", "rip");
    // TODO: add for all other regs.
  }

  Optional<unsigned> getID(std::string reg) const {
    if (reg == "rax" || reg == "eax" || reg == "ax")
      return 0;
    if (reg == "rdi" || reg == "edi" || reg == "di")
      return 1;
    if (reg == "rsi" || reg == "esi" || reg == "si")
      return 2;
    if (reg == "rdx" || reg == "edx" || reg == "dx")
      return 3;
    if (reg == "rcx" || reg == "ecx" || reg == "cx")
      return 4;
    if (reg == "r8" || reg == "r8d" || reg == "r8w")
      return 5;
    if (reg == "r9" || reg == "r9d" || reg == "r9w")
      return 6;
    if (reg == "r10" || reg == "r10d" || reg == "r10w")
      return 7;
    if (reg == "r11" || reg == "r11d" || reg == "r11w")
      return 8;
    if (reg == "rsp" || reg == "esp" || reg == "sp")
      return 9;
    if (reg == "rbx" || reg == "ebx" || reg == "bx")
      return 10;
    if (reg == "rbp" || reg == "ebp" || reg == "bp")
      return 11;
    if (reg == "r12" || reg == "r12d" || reg == "r12w")
      return 12;
    if (reg == "r13" || reg == "r13d" || reg == "r13w")
      return 13;
    if (reg == "r14" || reg == "r14d" || reg == "r14w")
      return 14;
    if (reg == "r15" || reg == "r15d" || reg == "r15w")
      return 15;
    if (reg == "rip")
      return 16;
    // TODO: Handle all regs.
    return None;
  }

  unsigned getRegSize(std::string reg) const {
    if (reg == "rax" || reg == "rdi" || reg == "rsi" ||
        reg == "rdx" || reg == "rcx" || reg == "r8" ||
        reg == "r9" || reg == "r10" || reg == "r11" ||
        reg == "rsp" || reg == "rbx" || reg == "rbp" ||
        reg == "r12" || reg == "r13" || reg == "r14" ||
        reg == "r15" || reg == "rip")
      return 64;
    if (reg == "eax" || reg == "edi" || reg == "esi" ||
        reg == "edx" || reg == "ecx" || reg == "r8d" ||
        reg == "r9d" || reg == "r10d" || reg == "r11d" ||
        reg == "esp" || reg == "ebx" || reg == "ebp" ||
        reg == "r12d" || reg == "r13d" || reg == "r14d" ||
        reg == "r15d")
      return 32;
    if (reg == "ax" || reg == "di" || reg == "si" ||
        reg == "dx" || reg == "cx" || reg == "r8w" ||
        reg == "r9w" || reg == "r10w" || reg == "r11w" ||
        reg == "sp" || reg == "bx" || reg == "bp" ||
        reg == "r12w" || reg == "r13w" || reg == "r14w" ||
        reg == "r15w")
      return 16;
    return 0;
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

  // Functions that are out of BT don't have any register value information
  // in corefiles, so we have nothing to start with.
  // FIXME: Should we propagate some values from previos frame?
  bool CREEnabled = false;

 public:
  // Init the curr reg values with the values from the 'regInfo' attribute,
  // which are the values read from corefile.
  ConcreteReverseExec(const MachineFunction *MF)
      : currentRegisterValues(MF->getCrashRegInfo()), mf(MF) {
    RegAliases =  RegisterMappings();
    if (MF->getCrashRegInfo().size())
      CREEnabled = true;
  }
  void dump();
  void updateCurrRegVal(std::string Reg, std::string Val);
  std::string getCurretValueInReg(const std::string &Reg);

  RegisterMappings& getRegAliasesInfo() {
    return RegAliases;
  }

  const MachineFunction *getMF() { return mf; }
  bool getIsCREEnabled() const { return CREEnabled; }

  // Reverse execution of the MI by updating the currentRegisterValues.
  void execute(const MachineInstr &MI);
};

#endif
