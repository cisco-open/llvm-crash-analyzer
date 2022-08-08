//===- TaintInfo.cpp ------------ Unit test ---------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/TaintAnalysis.h"

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
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"
#include "gtest/gtest.h"

using namespace llvm;

namespace {

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
  SMDiagnostic Diagnostic;
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
TEST(TaintInfo, locationEquivalence) {
  std::unique_ptr<LLVMTargetMachine> TM = createTargetMachine();
  ASSERT_TRUE(TM);

  StringRef MIRString = R"MIR(
--- |
  ; ModuleID = 'bin/struct1-0'
  source_filename = "bin/struct1-0"
  target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
  
  ; Materializable
  define void @foo() !dbg !2 {
  entry:
    unreachable
  }
  
  !llvm.dbg.cu = !{!0}
  
  !0 = distinct !DICompileUnit(language: DW_LANG_C, file: !1, producer: "llvm-crash-analyzer", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug)
  !1 = !DIFile(filename: "/nobackup/bseshadr/llvm-crash-anal/c_test_cases/struct1.c", directory: "/")
  !2 = distinct !DISubprogram(name: "foo", linkageName: "foo", scope: null, file: !1, line: 1, type: !3, scopeLine: 1, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !4)
  !3 = !DISubroutineType(types: !4)
  !4 = !{}

...
---
name:            foo
alignment:       16
exposesReturnsTwice: false
legalized:       false
regBankSelected: false
selected:        false
failedISel:      false
tracksRegLiveness: true
hasWinCFI:       false
registers:       []
liveins:         []
frameInfo:
  isFrameAddressTaken: false
  isReturnAddressTaken: false
  hasStackMap:     false
  hasPatchPoint:   false
  stackSize:       0
  offsetAdjustment: 0
  maxAlignment:    1
  adjustsStack:    false
  hasCalls:        false
  stackProtector:  ''
  maxCallFrameSize: 4294967295
  cvBytesOfCalleeSavedRegisters: 0
  hasOpaqueSPAdjustment: false
  hasVAStart:      false
  hasMustTailInVarArgFunc: false
  localFrameSize:  0
  savePoint:       ''
  restorePoint:    ''
fixedStack:      []
stack:           []
callSites:       []
debugValueSubstitutions: []
regInfo:         { GPRegs: 
    - { reg: rax, value: '0x0000000000000000' }
    - { reg: rbx, value: '0x0000000000000000' }
    - { reg: rcx, value: '0x000000000000000a' }
    - { reg: rdx, value: '0x00007ffe9b333dd8' }
    - { reg: rdi, value: '0x00007ffe9b333cc8' }
    - { reg: rsi, value: '0x00007ffe9b333dc8' }
    - { reg: rbp, value: '0x00007ffe9b333cb0' }
    - { reg: rsp, value: '0x00007ffe9b333cb0' }
    - { reg: r8, value: '0x00007f822de54da0' }
    - { reg: r9, value: '0x00007f822de54da0' }
    - { reg: r10, value: '0x0000000000000000' }
    - { reg: r11, value: '0x00007f822dc16630' }
    - { reg: r12, value: '0x00000000004004c0' }
    - { reg: r13, value: '0x00007ffe9b333dc0' }
    - { reg: r14, value: '0x0000000000000000' }
    - { reg: r15, value: '0x0000000000000000' }
    - { reg: rip, value: '0x00000000004005c6' }
    - { reg: rflags, value: '0x0000000000010206' }
    - { reg: cs, value: '0x0000000000000033' }
    - { reg: fs, value: '0x0000000000000000' }
    - { reg: gs, value: '0x0000000000000000' }
    - { reg: ss, value: '0x000000000000002b' }
    - { reg: ds, value: '0x0000000000000000' }
    - { reg: es, value: '0x0000000000000000' }
    - { reg: eax, value: '0x00000000' }
    - { reg: ebx, value: '0x00000000' }
    - { reg: ecx, value: '0x0000000a' }
    - { reg: edx, value: '0x9b333dd8' }
    - { reg: edi, value: '0x9b333cc8' }
    - { reg: esi, value: '0x9b333dc8' }
    - { reg: ebp, value: '0x9b333cb0' }
    - { reg: esp, value: '0x9b333cb0' }
    - { reg: r8d, value: '0x2de54da0' }
    - { reg: r9d, value: '0x2de54da0' }
    - { reg: r10d, value: '0x00000000' }
    - { reg: r11d, value: '0x2dc16630' }
    - { reg: r12d, value: '0x004004c0' }
    - { reg: r13d, value: '0x9b333dc0' }
    - { reg: r14d, value: '0x00000000' }
    - { reg: r15d, value: '0x00000000' }
    - { reg: ax, value: '0x0000' }
    - { reg: bx, value: '0x0000' }
    - { reg: cx, value: '0x000a' }
    - { reg: dx, value: '0x3dd8' }
    - { reg: di, value: '0x3cc8' }
    - { reg: si, value: '0x3dc8' }
    - { reg: bp, value: '0x3cb0' }
    - { reg: sp, value: '0x3cb0' }
    - { reg: r8w, value: '0x4da0' }
    - { reg: r9w, value: '0x4da0' }
    - { reg: r10w, value: '0x0000' }
    - { reg: r11w, value: '0x6630' }
    - { reg: r12w, value: '0x04c0' }
    - { reg: r13w, value: '0x3dc0' }
    - { reg: r14w, value: '0x0000' }
    - { reg: r15w, value: '0x0000' }
    - { reg: ah, value: '0x00' }
    - { reg: bh, value: '0x00' }
    - { reg: ch, value: '0x00' }
    - { reg: dh, value: '0x3d' }
    - { reg: al, value: '0x00' }
    - { reg: bl, value: '0x00' }
    - { reg: cl, value: '0x0a' }
    - { reg: dl, value: '0xd8' }
    - { reg: dil, value: '0xc8' }
    - { reg: sil, value: '0xc8' }
    - { reg: bpl, value: '0xb0' }
    - { reg: spl, value: '0xb0' }
    - { reg: r8l, value: '0xa0' }
    - { reg: r9l, value: '0xa0' }
    - { reg: r10l, value: '0x00' }
    - { reg: r11l, value: '0x30' }
    - { reg: r12l, value: '0xc0' }
    - { reg: r13l, value: '0xc0' }
    - { reg: r14l, value: '0x00' }
    - { reg: r15l, value: '0x00' } }
constants:       []
machineFunctionInfo: {}
crashOrder:     1
body:             |
  bb.0:
    liveins: $rbp, $rdi
  
    PUSH64r $rbp, implicit-def $rsp, implicit $rsp, debug-location !DILocation(line: 11, scope: !2)
    $rbp = MOV64rr $rsp, debug-location !DILocation(line: 11, scope: !2)
    MOV64mr $rbp, 1, $noreg, -8, $noreg, $rdi, debug-location !DILocation(line: 11, scope: !2)
    MOV64mi32 $rbp, 1, $noreg, -12, $noreg, 2, debug-location !DILocation(line: 11, scope: !2)
    MOV64mi32 $rbp, 1, $noreg, -20, $noreg, 2, debug-location !DILocation(line: 11, scope: !2)
    $rax = MOV64rm $rbp, 1, $noreg, -8, $noreg, debug-location !DILocation(line: 12, column: 9, scope: !2)
    $ecx = MOV32rm $rax, 1, $noreg, 0, $noreg, debug-location !DILocation(line: 12, column: 12, scope: !2)
    $rax = MOV64rm $rbp, 1, $noreg, -8, $noreg, debug-location !DILocation(line: 12, column: 16, scope: !2)
    $rax = MOV64rm $rax, 1, $noreg, 8, $noreg, debug-location !DILocation(line: 12, column: 19, scope: !2)
    $ecx = crash-start ADD32rm $ecx, $rax, 1, $noreg, 0, $noreg, implicit-def $eflags, debug-location !DILocation(line: 12, column: 13, scope: !2)
    $eax = MOV32rr $ecx, debug-location !DILocation(line: 12, column: 2, scope: !2)
    $rbp = POP64r implicit-def $rsp, implicit $rsp, debug-location !DILocation(line: 12, column: 2, scope: !2)
    RETQ debug-location !DILocation(line: 12, column: 2, scope: !2)

...
)MIR";

  LLVMContext Context;
  std::unique_ptr<MIRParser> MIR;
  MachineModuleInfo MMI(TM.get());
  std::unique_ptr<Module> M =
      parseMIR(Context, MIR, *TM, MIRString, "instrInterpretation", MMI);
  ASSERT_TRUE(M);

  Function *F = M->getFunction("foo");
  auto *MF = MMI.getMachineFunction(*F);
  ASSERT_TRUE(MF);

  bool CrashSequenceStarted = false;

  auto TRI = MF->getSubtarget().getRegisterInfo();
  auto TII = MF->getSubtarget().getInstrInfo();
  ASSERT_TRUE(TRI);
  ASSERT_TRUE(TII);

  crash_analyzer::TaintAnalysis TA(false);
  // Here we simulate backward Taint Analysis, but we are interested in
  // inspecting Taint Info management only.
  for (auto MBBIt = MF->rbegin(); MBBIt != MF->rend(); ++MBBIt) {
    auto &MBB = *MBBIt;
    crash_analyzer::TaintInfo FirstImmTi, SecImmTi;
    bool FirstStore = true;
    for (auto MIIt = MBB.rbegin(); MIIt != MBB.rend(); ++MIIt) {
      auto &MI = *MIIt;
      if (MI.getFlag(MachineInstr::CrashStart)) {
        CrashSequenceStarted = true;
        continue;
      }
      if (!CrashSequenceStarted)
        continue;
      if (MI.isBranch())
        continue;
      // We reached the end of the frame.
      if (TII->isPush(MI))
        break;
      if (TII->isLoad(MI)) {
        auto DestSrc = TII->getDestAndSrc(MI);
        if (!DestSrc)
          continue;
        TA.printDestSrcInfo(*DestSrc, MI);

        crash_analyzer::TaintInfo SrcTi, DestTi;
        SrcTi.Op = DestSrc->Source;
        SrcTi.Offset = DestSrc->SrcOffset;
        if (SrcTi.Offset)
          TA.calculateMemAddr(SrcTi);

        DestTi.Op = DestSrc->Destination;
        DestTi.Offset = DestSrc->DestOffset;
        if (DestTi.Offset)
          TA.calculateMemAddr(DestTi);

        // For MI $rax = MOV64rm $rax, 1, $noreg, 8, $noreg
        // Confirm that {reg: $rax} is not equal to {reg:$rax; off:8} in the
        // case where we can't calculate Concrete Memory Address.
        ASSERT_FALSE(DestTi == SrcTi);
      }
      if (TII->isStore(MI)) {
        auto DestSrc = TII->getDestAndSrc(MI);
        if (!DestSrc)
          continue;
	    if (!DestSrc->Source->isImm())
          continue;
        TA.printDestSrcInfo(*DestSrc, MI);
        // Extract immediate ({imm:2}) operands from Store instructions.
        if (FirstStore) {
          // From MOV64mi32 $rbp, 1, $noreg, -20, $noreg, 2,
          FirstImmTi.Op = DestSrc->Source;
          FirstImmTi.Offset = DestSrc->SrcOffset;
          if (FirstImmTi.Offset)
            TA.calculateMemAddr(FirstImmTi);
          FirstStore = false;
        } else {
          // From MOV64mi32 $rbp, 1, $noreg, -20, $noreg, 2,
          SecImmTi.Op = DestSrc->Source;
          SecImmTi.Offset = DestSrc->SrcOffset;
          if (SecImmTi.Offset)
            TA.calculateMemAddr(SecImmTi);
          // Compare immediate TaintInfos ({imm:2} and {imm:2}).
          ASSERT_TRUE(FirstImmTi == SecImmTi);
        }
      }
    }
  }
}

} // namespace