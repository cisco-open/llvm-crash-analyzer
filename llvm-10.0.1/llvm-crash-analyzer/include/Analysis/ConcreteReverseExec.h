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
using namespace crash_analyzer;

using RegAliasTripple =
  std::tuple<std::string, std::string, std::string, std::string>;

// TODO: This should be Target independent, so move it
// to llvm/Target/x86 part.
struct RegisterMappings {
  // This will be mapped into register aliases.
  // e.g. rax, eax, ax will hold a same id.
  std::unordered_map<unsigned, RegAliasTripple> regMap;
public:
  RegisterMappings() {
    regMap[0] = std::make_tuple("rax", "eax", "ax", "al");
    regMap[1] = std::make_tuple("rdi", "edi", "di", "dil");
    regMap[2] = std::make_tuple("rsi", "esi", "si", "sil");
    regMap[3] = std::make_tuple("rdx", "edx", "dx", "dl");
    regMap[4] = std::make_tuple("rcx", "ecx", "cx", "cl");
    regMap[5] = std::make_tuple("r8", "r8d", "r8w", "r8b");
    regMap[6] = std::make_tuple("r9", "r9d", "r9w", "r9b");
    regMap[7] = std::make_tuple("r10", "r10d", "r10w", "r10b");
    regMap[8] = std::make_tuple("r11", "r11d", "r11w", "r11b");
    regMap[9] = std::make_tuple("rsp", "esp", "sp", "spl");
    regMap[10] = std::make_tuple("rbx", "ebx", "bx", "bl");
    regMap[11] = std::make_tuple("rbp", "ebp", "bp", "bpl");
    regMap[12] = std::make_tuple("r12", "r12d", "r12w", "r12b");
    regMap[13] = std::make_tuple("r13", "r13d", "r13w", "r13b");
    regMap[14] = std::make_tuple("r14", "r14d", "r14w", "r14b");
    regMap[15] = std::make_tuple("r15", "r15d", "r15w", "r15b");
    regMap[16] = std::make_tuple("rip", "rip", "rip", "rip");
    // TODO: add for all other regs.
  }

  Optional<unsigned> getID(std::string reg) const {
    if (reg == "rax" || reg == "eax" || reg == "ax" ||
        reg == "al")
      return 0;
    if (reg == "rdi" || reg == "edi" || reg == "di" ||
        reg == "dil")
      return 1;
    if (reg == "rsi" || reg == "esi" || reg == "si" ||
        reg == "sil")
      return 2;
    if (reg == "rdx" || reg == "edx" || reg == "dx" ||
        reg == "dl")
      return 3;
    if (reg == "rcx" || reg == "ecx" || reg == "cx" ||
        reg == "cl")
      return 4;
    if (reg == "r8" || reg == "r8d" || reg == "r8w" ||
        reg == "r8b")
      return 5;
    if (reg == "r9" || reg == "r9d" || reg == "r9w" ||
        reg == "r9b")
      return 6;
    if (reg == "r10" || reg == "r10d" || reg == "r10w" ||
        reg == "r10b")
      return 7;
    if (reg == "r11" || reg == "r11d" || reg == "r11w" ||
        reg == "r11b")
      return 8;
    if (reg == "rsp" || reg == "esp" || reg == "sp" ||
        reg == "spl")
      return 9;
    if (reg == "rbx" || reg == "ebx" || reg == "bx" ||
        reg == "bl")
      return 10;
    if (reg == "rbp" || reg == "ebp" || reg == "bp" ||
        reg == "bpl")
      return 11;
    if (reg == "r12" || reg == "r12d" || reg == "r12w" ||
        reg == "r12b")
      return 12;
    if (reg == "r13" || reg == "r13d" || reg == "r13w" ||
        reg == "r13b")
      return 13;
    if (reg == "r14" || reg == "r14d" || reg == "r14w" ||
        reg == "r14b")
      return 14;
    if (reg == "r15" || reg == "r15d" || reg == "r15w" ||
        reg == "r15b")
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
    if (reg == "al" || reg == "dil" || reg == "sil" ||
        reg == "dl" || reg == "cl" || reg == "spl" ||
        reg == "bl" || reg == "bpl" || reg == "r8b" ||
        reg == "r9b" || reg == "r10b" || reg == "r11b" ||
        reg == "r12b" || reg == "r13b" || reg == "r14b")
      return 8;
    return 0;
  }

  RegAliasTripple& getRegMap(unsigned id) const {
    return const_cast<RegAliasTripple&>(regMap.at(id));
  }
};

// Class that implements the Concrete Reverse Execution.
// TODO: Since we rely on corefile content during CRE and TA,
// by updating register values, we need to remember changes
// to memory as well, since there could be instructions
// that may store.
class ConcreteReverseExec {
  // This represents current values in the registers.
  MachineFunction::RegisterCrashInfo currentRegisterValues;
  const MachineFunction *mf;

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
  // FIXME: This is used for debugging purposes only -- DELETEME.
  void dump2();
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
