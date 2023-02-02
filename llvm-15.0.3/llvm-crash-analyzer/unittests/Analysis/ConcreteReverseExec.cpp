//===- ConcreteReverseExec.cpp ------------ Unit test ---------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/ConcreteReverseExec.h"

#include "llvm/CodeGen/MIRParser/MIRParser.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/TargetFrameLowering.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetLowering.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/ModuleSlotTracker.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"
#include "gtest/gtest.h"

using namespace llvm;

namespace {
//#include "MFCommon.inc"

std::unique_ptr<LLVMTargetMachine> createTargetMachine() {
  auto TT(Triple::normalize("x86_64-unknown-unknown"));
  std::string CPU("");
  std::string FS("");

  LLVMInitializeX86TargetInfo();
  LLVMInitializeX86Target();
  LLVMInitializeX86TargetMC();

  std::string Error;
  const Target *TheTarget = TargetRegistry::lookupTarget(TT, Error);
  assert(TheTarget);

  return std::unique_ptr<LLVMTargetMachine>(
      static_cast<LLVMTargetMachine *>(TheTarget->createTargetMachine(
          TT, CPU, FS, TargetOptions(), None, None, CodeGenOpt::Default)));
}

std::unique_ptr<Module> parseMIR(LLVMContext &Context,
                                 std::unique_ptr<MIRParser> &MIR,
                                 const TargetMachine &TM, StringRef MIRCode,
                                 const char *FuncName, MachineModuleInfo &MMI) {
  std::unique_ptr<MemoryBuffer> MBuffer = MemoryBuffer::getMemBuffer(MIRCode);
  MIR = createMIRParser(std::move(MBuffer), Context);
  if (!MIR)
    return nullptr;

  std::unique_ptr<Module> M = MIR->parseIRModule();
  if (!M)
    return nullptr;

  M->setDataLayout(TM.createDataLayout());

  if (MIR->parseMachineFunctions(*M, MMI))
    return nullptr;

  return M;
}

// This is dummy unit test.
TEST(ConcreteReverseExec, instrInterpretation) {
  // LLVMContext Ctx;
  // Module Mod("Module", Ctx);
  // auto MF = createMachineFunction(Ctx, Mod);
  std::unique_ptr<LLVMTargetMachine> TM = createTargetMachine();
  ASSERT_TRUE(TM);

  StringRef MIRString = R"MIR(
--- |
  ; ModuleID = 'null-cmp'
  source_filename = "null-cmp"
  target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"

  ; Materializable
  define void @do_cmp() !dbg !2 {
  entry:
    unreachable
  }

  !llvm.dbg.cu = !{!0}

  !0 = distinct !DICompileUnit(language: DW_LANG_C, file: !1, producer: "llvm-crash-analyzer", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug)
  !1 = !DIFile(filename: "/nobackup/djtodoro/llvm_trunk/NEW/llvm-crash-analyzer/CISCO-git/llvm-crash-anal/c_test_cases/test3.c", directory: "/")
  !2 = distinct !DISubprogram(name: "do_cmp", linkageName: "do_cmp", scope: null, file: !1, line: 1, type: !3, scopeLine: 1, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !4)
  !3 = !DISubroutineType(types: !4)
  !4 = !{}

...
---
name:            do_cmp
alignment:       16
tracksRegLiveness: true
regInfo:         { GPRegs:
    - { reg: rax, value: '0x0000000000000009' }
    - { reg: rbx, value: '0x0000000000000000' }
    - { reg: rcx, value: '0x0000000000000000' }
    - { reg: rdx, value: '0x00007fffe044abb8' }
    - { reg: rdi, value: '0x0000000000000000' }
    - { reg: rsi, value: '0x00007fffe044aba8' }
    - { reg: rbp, value: '0x00007fffe044aa90' }
    - { reg: rsp, value: '0x00007fffe044aa90' }
    - { reg: r8, value: '0x00007f15c0269e80' }
    - { reg: r9, value: '0x0000000000000000' }
    - { reg: r10, value: '0x00007fffe044a5e0' }
    - { reg: r11, value: '0x00007f15bfec3450' }
    - { reg: r12, value: '0x0000000000401050' }
    - { reg: r13, value: '0x00007fffe044aba0' }
    - { reg: r14, value: '0x0000000000000000' }
    - { reg: r15, value: '0x0000000000000000' }
    - { reg: rip, value: '0x0000000000401169' }
    - { reg: rflags, value: '0x0000000000010206' }
    - { reg: cs, value: '0x0000000000000033' }
    - { reg: fs, value: '0x0000000000000000' }
    - { reg: gs, value: '0x0000000000000000' }
    - { reg: ss, value: '0x000000000000002b' }
    - { reg: ds, value: '0x0000000000000000' }
    - { reg: es, value: '0x0000000000000000' }
    - { reg: eax, value: '0x00000009' }
    - { reg: ebx, value: '0x00000000' }
    - { reg: ecx, value: '0x00000000' }
    - { reg: edx, value: '0xe044abb8' }
    - { reg: edi, value: '0x00000000' }
    - { reg: esi, value: '0xe044aba8' }
    - { reg: ebp, value: '0xe044aa90' }
    - { reg: esp, value: '0xe044aa90' }
    - { reg: r8d, value: '0xc0269e80' }
    - { reg: r9d, value: '0x00000000' }
    - { reg: r10d, value: '0xe044a5e0' }
    - { reg: r11d, value: '0xbfec3450' }
    - { reg: r12d, value: '0x00401050' }
    - { reg: r13d, value: '0xe044aba0' }
    - { reg: r14d, value: '0x00000000' }
    - { reg: r15d, value: '0x00000000' }
    - { reg: ax, value: '0x0009' }
    - { reg: bx, value: '0x0000' }
    - { reg: cx, value: '0x0000' }
    - { reg: dx, value: '0xabb8' }
    - { reg: di, value: '0x0000' }
    - { reg: si, value: '0xaba8' }
    - { reg: bp, value: '0xaa90' }
    - { reg: sp, value: '0xaa90' }
    - { reg: r8w, value: '0x9e80' }
    - { reg: r9w, value: '0x0000' }
    - { reg: r10w, value: '0xa5e0' }
    - { reg: r11w, value: '0x3450' }
    - { reg: r12w, value: '0x1050' }
    - { reg: r13w, value: '0xaba0' }
    - { reg: r14w, value: '0x0000' }
    - { reg: r15w, value: '0x0000' }
    - { reg: ah, value: '0x00' }
    - { reg: bh, value: '0x00' }
    - { reg: ch, value: '0x00' }
    - { reg: dh, value: '0xab' }
    - { reg: al, value: '0x09' }
    - { reg: bl, value: '0x00' }
    - { reg: cl, value: '0x00' }
    - { reg: dl, value: '0xb8' }
    - { reg: dil, value: '0x00' }
    - { reg: sil, value: '0xa8' }
    - { reg: bpl, value: '0x90' }
    - { reg: spl, value: '0x90' }
    - { reg: r8l, value: '0x80' }
    - { reg: r9l, value: '0x00' }
    - { reg: r10l, value: '0xe0' }
    - { reg: r11l, value: '0x50' }
    - { reg: r12l, value: '0x50' }
    - { reg: r13l, value: '0xa0' }
    - { reg: r14l, value: '0x00' }
    - { reg: r15l, value: '0x00' } }
crashOrder:     1
body:             |
  bb.0:
    successors: %bb.1(0x40000000), %bb.2(0x40000000)
    liveins: $rbp, $rdi

    PUSH64r $rbp, implicit-def $rsp, implicit $rsp, debug-location !DILocation(line: 4, scope: !2)
    $rbp = MOV64rr $rsp, debug-location !DILocation(line: 4, scope: !2)
    MOV64mr $rbp, 1, $noreg, -8, $noreg, $rdi, debug-location !DILocation(line: 4, scope: !2)
    MOV32mi $rbp, 1, $noreg, -12, $noreg, 8, debug-location !DILocation(line: 5, column: 7, scope: !2)
    CMP32mi8 $rbp, 1, $noreg, -12, $noreg, 0, implicit-def $eflags, debug-location !DILocation(line: 6, column: 9, scope: !2)
    JCC_4 %bb.2, 4, implicit $eflags, debug-location !DILocation(line: 6, column: 7, scope: !2)

  bb.1:
    successors: %bb.2(0x80000000)
    liveins: $rbp

    $eax = MOV32rm $rbp, 1, $noreg, -12, $noreg, debug-location !DILocation(line: 7, column: 5, scope: !2)
    $eax = ADD32ri8 $eax, 1, implicit-def $eflags, debug-location !DILocation(line: 7, column: 5, scope: !2)
    MOV32mr $rbp, 1, $noreg, -12, $noreg, $eax, debug-location !DILocation(line: 7, column: 5, scope: !2)

  bb.2:
    successors: %bb.3(0x40000000), %bb.4(0x40000000)
    liveins: $rbp

    $eax = MOV32rm $rbp, 1, $noreg, -12, $noreg, debug-location !DILocation(line: 8, column: 7, scope: !2)
    $rcx = MOV64rm $rbp, 1, $noreg, -8, $noreg, debug-location !DILocation(line: 8, column: 13, scope: !2)
    crash-start CMP32rm $eax, $rcx, 1, $noreg, 0, $noreg, implicit-def $eflags, debug-location !DILocation(line: 8, column: 9, scope: !2)
    JCC_4 %bb.4, 5, implicit $eflags, debug-location !DILocation(line: 8, column: 7, scope: !2)

  bb.3:
    successors: %bb.4(0x80000000)
    liveins: $rbp

    $eax = MOV32rm $rbp, 1, $noreg, -12, $noreg, debug-location !DILocation(line: 9, column: 5, scope: !2)
    $eax = ADD32ri8 $eax, -1, implicit-def $eflags, debug-location !DILocation(line: 9, column: 5, scope: !2)
    MOV32mr $rbp, 1, $noreg, -12, $noreg, $eax, debug-location !DILocation(line: 9, column: 5, scope: !2)

  bb.4:
    liveins: $rbp

    $eax = MOV32rm $rbp, 1, $noreg, -12, $noreg, debug-location !DILocation(line: 10, column: 10, scope: !2)
    $rbp = POP64r implicit-def $rsp, implicit $rsp, debug-location !DILocation(line: 10, column: 3, scope: !2)
    RET64 debug-location !DILocation(line: 10, column: 3, scope: !2)
)MIR";

  LLVMContext Context;
  std::unique_ptr<MIRParser> MIR;
  MachineModuleInfo MMI(TM.get());
  std::unique_ptr<Module> M =
      parseMIR(Context, MIR, *TM, MIRString, "instrInterpretation", MMI);
  ASSERT_TRUE(M);

  Function *F = M->getFunction("do_cmp");
  auto *MF = MMI.getMachineFunction(*F);
  ASSERT_TRUE(MF);

  ConcreteReverseExec ReverseExecutionRecord(MF);
  bool CrashSequenceStarted = false;

  auto TRI = MF->getSubtarget().getRegisterInfo();
  auto TII = MF->getSubtarget().getInstrInfo();
  ASSERT_TRUE(TRI);
  ASSERT_TRUE(TII);

  // Here we simulate backward Taint Analysis, but we are interested in
  // Concrete Reverse Execution only.
  for (auto MBBIt = MF->rbegin(); MBBIt != MF->rend(); ++MBBIt) {
    auto &MBB = *MBBIt;
    for (auto MIIt = MBB.rbegin(); MIIt != MBB.rend(); ++MIIt) {
      auto &MI = *MIIt;
      if (MI.getFlag(MachineInstr::CrashStart))
        CrashSequenceStarted = true;
      if (!CrashSequenceStarted)
        continue;

      Optional<Register> Reg = None;
      if (MI.getNumOperands() && MI.getOperand(0).isReg())
        Reg = MI.getOperand(0).getReg();
      // After an ADD is executed in the reverse order
      // we should have the register value detracted for the Imm value.
      if (Reg) {
        // Test for $eax = ADD32ri8 $eax(tied-def 0), 1.
        if (TII->isAddImmediate(MI, *Reg)) {
          std::string RegName = TRI->getRegAsmName(*Reg).lower();
          ReverseExecutionRecord.updateCurrRegVal(RegName, "0x00000009");
          auto regVal = ReverseExecutionRecord.getCurretValueInReg(RegName);
          ASSERT_TRUE(RegName == "eax");
          ASSERT_TRUE(regVal == "0x00000009");
        }
      }
      ReverseExecutionRecord.execute(MI);
      if (Reg) {
        // Test for $eax = ADD32ri8 $eax(tied-def 0), 1.
        if (TII->isAddImmediate(MI, *Reg)) {
          std::string RegName = TRI->getRegAsmName(*Reg).lower();
          auto regVal = ReverseExecutionRecord.getCurretValueInReg(RegName);
          ASSERT_TRUE(RegName == "eax");
          ASSERT_TRUE(regVal == "0x00000008");
        }
      }
    }
  }
}
} // namespace
