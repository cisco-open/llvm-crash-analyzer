//==- CATargetInfo.cpp - Crash Analyzer Target Information
//------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements the CATargetInfo class and its derivates.
//
//===----------------------------------------------------------------------===//

#include "Target/CATargetInfo.h"

const Triple *CATargetInfo::TT = nullptr;

X86CATargetInfo::X86CATargetInfo() {
  RegMap[0] = std::make_tuple("rax", "eax", "ax", "al");
  RegMap[1] = std::make_tuple("rdi", "edi", "di", "dil");
  RegMap[2] = std::make_tuple("rsi", "esi", "si", "sil");
  RegMap[3] = std::make_tuple("rdx", "edx", "dx", "dl");
  RegMap[4] = std::make_tuple("rcx", "ecx", "cx", "cl");
  RegMap[5] = std::make_tuple("r8", "r8d", "r8w", "r8b");
  RegMap[6] = std::make_tuple("r9", "r9d", "r9w", "r9b");
  RegMap[7] = std::make_tuple("r10", "r10d", "r10w", "r10b");
  RegMap[8] = std::make_tuple("r11", "r11d", "r11w", "r11b");
  RegMap[9] = std::make_tuple("rsp", "esp", "sp", "spl");
  RegMap[10] = std::make_tuple("rbx", "ebx", "bx", "bl");
  RegMap[11] = std::make_tuple("rbp", "ebp", "bp", "bpl");
  RegMap[12] = std::make_tuple("r12", "r12d", "r12w", "r12b");
  RegMap[13] = std::make_tuple("r13", "r13d", "r13w", "r13b");
  RegMap[14] = std::make_tuple("r14", "r14d", "r14w", "r14b");
  RegMap[15] = std::make_tuple("r15", "r15d", "r15w", "r15b");
  RegMap[16] = std::make_tuple("rip", "eip", "ip", "ip");
  // TODO: add for all other regs.
}

Optional<unsigned> X86CATargetInfo::getID(std::string RegName) const {
  if (RegName == "rax" || RegName == "eax" || RegName == "ax" ||
      RegName == "al")
    return 0;
  if (RegName == "rdi" || RegName == "edi" || RegName == "di" ||
      RegName == "dil")
    return 1;
  if (RegName == "rsi" || RegName == "esi" || RegName == "si" ||
      RegName == "sil")
    return 2;
  if (RegName == "rdx" || RegName == "edx" || RegName == "dx" ||
      RegName == "dl")
    return 3;
  if (RegName == "rcx" || RegName == "ecx" || RegName == "cx" ||
      RegName == "cl")
    return 4;
  if (RegName == "r8" || RegName == "r8d" || RegName == "r8w" ||
      RegName == "r8b")
    return 5;
  if (RegName == "r9" || RegName == "r9d" || RegName == "r9w" ||
      RegName == "r9b")
    return 6;
  if (RegName == "r10" || RegName == "r10d" || RegName == "r10w" ||
      RegName == "r10b")
    return 7;
  if (RegName == "r11" || RegName == "r11d" || RegName == "r11w" ||
      RegName == "r11b")
    return 8;
  if (RegName == "rsp" || RegName == "esp" || RegName == "sp" ||
      RegName == "spl")
    return 9;
  if (RegName == "rbx" || RegName == "ebx" || RegName == "bx" ||
      RegName == "bl")
    return 10;
  if (RegName == "rbp" || RegName == "ebp" || RegName == "bp" ||
      RegName == "bpl")
    return 11;
  if (RegName == "r12" || RegName == "r12d" || RegName == "r12w" ||
      RegName == "r12b")
    return 12;
  if (RegName == "r13" || RegName == "r13d" || RegName == "r13w" ||
      RegName == "r13b")
    return 13;
  if (RegName == "r14" || RegName == "r14d" || RegName == "r14w" ||
      RegName == "r14b")
    return 14;
  if (RegName == "r15" || RegName == "r15d" || RegName == "r15w" ||
      RegName == "r15b")
    return 15;
  if (RegName == "rip" || RegName == "eip" || RegName == "ip")
    return 16;
  // TODO: Handle all regs.
  return None;
}

unsigned X86CATargetInfo::getRegSize(std::string RegName) const {
  if (RegName == "rax" || RegName == "rdi" || RegName == "rsi" ||
      RegName == "rdx" || RegName == "rcx" || RegName == "r8" ||
      RegName == "r9" || RegName == "r10" || RegName == "r11" ||
      RegName == "rsp" || RegName == "rbx" || RegName == "rbp" ||
      RegName == "r12" || RegName == "r13" || RegName == "r14" ||
      RegName == "r15" || RegName == "rip")
    return 64;
  if (RegName == "eax" || RegName == "edi" || RegName == "esi" ||
      RegName == "edx" || RegName == "ecx" || RegName == "r8d" ||
      RegName == "r9d" || RegName == "r10d" || RegName == "r11d" ||
      RegName == "esp" || RegName == "ebx" || RegName == "ebp" ||
      RegName == "r12d" || RegName == "r13d" || RegName == "r14d" ||
      RegName == "r15d" || RegName == "eip")
    return 32;
  if (RegName == "ax" || RegName == "di" || RegName == "si" ||
      RegName == "dx" || RegName == "cx" || RegName == "r8w" ||
      RegName == "r9w" || RegName == "r10w" || RegName == "r11w" ||
      RegName == "sp" || RegName == "bx" || RegName == "bp" ||
      RegName == "r12w" || RegName == "r13w" || RegName == "r14w" ||
      RegName == "r15w" || RegName == "ip")
    return 16;
  if (RegName == "al" || RegName == "dil" || RegName == "sil" ||
      RegName == "dl" || RegName == "cl" || RegName == "spl" ||
      RegName == "bl" || RegName == "bpl" || RegName == "r8b" ||
      RegName == "r9b" || RegName == "r10b" || RegName == "r11b" ||
      RegName == "r12b" || RegName == "r13b" || RegName == "r14b")
    return 8;
  return 0;
}

bool X86CATargetInfo::isRetValRegister(std::string RegName) const {
  if (RegName == "rax" || RegName == "eax" || RegName == "ax" ||
      RegName == "al" || RegName == "xmm0")
    return true;
  return false;
}

bool X86CATargetInfo::isPCRegister(std::string RegName) const {
  if (RegName == "rip" || RegName == "eip" || RegName == "ip")
    return true;
  return false;
}

Optional<std::string> X86CATargetInfo::getPC() const {
  switch (TT->getArch()) {
  case Triple::x86_64:
    return static_cast<std::string>("rip");
  case Triple::x86:
    return static_cast<std::string>("eip");
  default:
    return llvm::None;
  }
}

bool X86CATargetInfo::isSPRegister(std::string RegName) const {
  if (RegName == "rsp" || RegName == "esp" || RegName == "sp" ||
      RegName == "spl")
    return true;
  return false;
}

bool X86CATargetInfo::isBPRegister(std::string RegName) const {
  if (RegName == "rbp" || RegName == "ebp" || RegName == "bp" ||
      RegName == "bpl")
    return true;
  return false;
}

bool X86CATargetInfo::isParamFwdRegister(std::string RegName) const {
  if (RegName == "rdi" || RegName == "edi" || RegName == "di" ||
      RegName == "dil")
    return true;
  if (RegName == "rsi" || RegName == "esi" || RegName == "si" ||
      RegName == "sil")
    return true;
  if (RegName == "rdx" || RegName == "edx" || RegName == "dx" ||
      RegName == "dl")
    return true;
  if (RegName == "rcx" || RegName == "ecx" || RegName == "cx" ||
      RegName == "cl")
    return true;
  if (RegName == "r8" || RegName == "r8d" || RegName == "r8w" ||
      RegName == "r8b")
    return true;
  if (RegName == "r9" || RegName == "r9d" || RegName == "r9w" ||
      RegName == "r9b")
    return true;
  return false;
}

Optional<unsigned> X86CATargetInfo::getRegister(std::string RegName,
                                                const MachineInstr *MI) const {
  auto TRI = MI->getMF()->getSubtarget().getRegisterInfo();
  if (!TRI)
    return None;
  unsigned N = 1000;
  for (unsigned I = 0; I < N; ++I) {
    std::string CurName = TRI->getRegAsmName(I).lower();
    if (CurName == RegName)
      return I;
  }
  return None;
}
