//===- RegisterEquivalence.cpp ------------ Unit test ---------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/RegisterEquivalence.h"

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
  // SMDiagnostic Diagnostic;
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

TEST(RegisterEquivalence, regEq) {
  std::unique_ptr<LLVMTargetMachine> TM = createTargetMachine();
  ASSERT_TRUE(TM);

  StringRef MIRString = R"MIR(
--- |
  ; ModuleID = 'a.out'
  source_filename = "a.out"
  target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
  
  ; Materializable
  define void @foo() !dbg !5 {
  entry:
    unreachable
  }
  
  !llvm.dbg.cu = !{!0}
  
  !0 = distinct !DICompileUnit(language: DW_LANG_C, file: !1, producer: "llvm-crash-analyzer", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug)
  !1 = !DIFile(filename: "/nobackup/djtodoro/llvm_trunk/NEW/llvm-crash-analyzer/CISCO-git/test-dfg/ptr-to-ptr/test.c", directory: "/")
  !3 = !DISubroutineType(types: !4)
  !4 = !{}
  !5 = distinct !DISubprogram(name: "foo", linkageName: "foo", scope: null, file: !1, line: 1, type: !3, scopeLine: 1, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !4)

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
regInfo:         { GPRegs: [] }
constants:       []
machineFunctionInfo: {}
crashOrder:     0
body:             |
  bb.0:
    liveins: $rbp, $rdi, $rsi
  
    PUSH64r $rbp, implicit-def $rsp, implicit $rsp, debug-location !DILocation(line: 3, scope: !5)
    $rbp = MOV64rr $rsp, debug-location !DILocation(line: 3, scope: !5)
    MOV64mr $rbp, 1, $noreg, -8, $noreg, $rdi, debug-location !DILocation(line: 3, scope: !5)
    $rax = MOV64rm $rbp, 1, $noreg, -8, $noreg, debug-location !DILocation(line: 4, column: 2, scope: !5)
    MOV64mr $rsi, 1, $noreg, 16, $noreg, $rax, debug-location !DILocation(line: 4, scope: !5)
    $rbp = XOR64rr undef $rbp, undef $rbp, implicit-def $eflags, debug-location !DILocation(line: 4, column: 2, scope: !5)
    MOV64mi32 $rax, 1, $noreg, 0, $noreg, 0, debug-location !DILocation(line: 4, column: 4, scope: !5)
    $eax = MOV32ri 111111, debug-location !DILocation(line: 4, column: 4, scope: !5)
    $rax = MOV64rm $rax, 1, $noreg, -8, $noreg, debug-location !DILocation(line: 4, column: 4, scope: !5)
    $rbp = POP64r implicit-def $rsp, implicit $rsp, debug-location !DILocation(line: 5, column: 1, scope: !5)
    crash-start RET64 debug-location !DILocation(line: 5, column: 1, scope: !5)

...
)MIR";

  LLVMContext Context;
  std::unique_ptr<MIRParser> MIR;
  MachineModuleInfo MMI(TM.get());
  std::unique_ptr<Module> M =
      parseMIR(Context, MIR, *TM, MIRString, "reg equivalance", MMI);
  ASSERT_TRUE(M);

  Function *F = M->getFunction("foo");
  auto *MF = MMI.getMachineFunction(*F);
  ASSERT_TRUE(MF);

  auto TII = MF->getSubtarget().getInstrInfo();

  RegisterEquivalence REAnalysis;
  REAnalysis.init(const_cast<MachineFunction &>(*MF));
  REAnalysis.run(const_cast<MachineFunction &>(*MF));

  for (auto &MBB : *MF) {
    for (auto &MI : MBB) {
      // Test load impact on RegisterEquivalence.
      // Confirm that RegisterEquivalence is a symmetric relation.
      if (TII->isLoad(MI)) {
        REAnalysis.dumpRegTableAfterMI(&MI);
        unsigned Reg1 = MI.getOperand(0).getReg();
        unsigned Reg2 = MI.getOperand(1).getReg();
        int64_t Offset = MI.getOperand(4).getImm();
        // If Source BaseReg is same as DestReg, equivalance is not valid.
        ASSERT_TRUE((Reg1 == Reg2) !=
                    REAnalysis.isEquivalent(MI, {Reg1}, {Reg2, Offset, true}));
        ASSERT_TRUE((Reg1 == Reg2) !=
                    REAnalysis.isEquivalent(MI, {Reg2, Offset, true}, {Reg1}));

        ASSERT_TRUE((Reg1 == Reg2) != REAnalysis.verifyEquivalenceTransitivity(
                                          MI, {Reg1}, {Reg2, Offset, true}));
        ASSERT_TRUE((Reg1 == Reg2) != REAnalysis.verifyEquivalenceTransitivity(
                                          MI, {Reg2, Offset, true}, {Reg1}));
        continue;
      }
      // Test store impact on RegisterEquivalence.
      if (TII->isStore(MI)) {
        REAnalysis.dumpRegTableAfterMI(&MI);
        auto SrcOp = MI.getOperand(5);
        // Store from Register to memory.
        if (SrcOp.isReg()) {
          unsigned BaseReg = MI.getOperand(0).getReg();
          unsigned SrcReg = MI.getOperand(5).getReg();
          int64_t Offset = MI.getOperand(3).getImm();
          ASSERT_TRUE(
              REAnalysis.isEquivalent(MI, {SrcReg}, {BaseReg, Offset, true}));
          ASSERT_TRUE(
              REAnalysis.isEquivalent(MI, {BaseReg, Offset, true}, {SrcReg}));

          ASSERT_TRUE(REAnalysis.verifyEquivalenceTransitivity(
              MI, {BaseReg, Offset, true}, {SrcReg}));
          ASSERT_TRUE(REAnalysis.verifyEquivalenceTransitivity(
              MI, {SrcReg}, {BaseReg, Offset, true}));
        } else {
          // Store constant in memory.
          unsigned BaseReg = MI.getOperand(0).getReg();
          ASSERT_TRUE(MI.getOperand(5).isImm());
          int64_t Offset = MI.getOperand(3).getImm();
          ASSERT_FALSE(REAnalysis.isEquivalent(MI, {BaseReg, Offset},
                                               {BaseReg, Offset, true}));
        }
        continue;
      }
      if (TII->isXORSimplifiedSetToZero(MI)) {
        REAnalysis.dumpRegTableAfterMI(&MI);
        unsigned Reg1 = MI.getOperand(0).getReg();
        // Verify that redefined Reg1 ($rbp) triggers invalidation of
        // deref->(Reg1)+(Offset) (deref->($rbp)+(-8)).
        auto Prev = std::next(MI.getReverseIterator());
        std::set<RegisterOffsetPair> EqR =
            REAnalysis.getEqRegsAfterMI(&*Prev, {Reg1, -8, true});
        if (EqR.size()) {
          ASSERT_TRUE(
              REAnalysis.getEqRegsAfterMI(&MI, {Reg1, -8, true}).size() == 1);
        }
        continue;
      }
      // Test Mov Immediate impact ($eax = MOV32ri 111111).
      // Verify that redefined Reg1 ($eax) triggers invalidation
      // of all super/sub regs ($rax).
      if (MI.getNumOperands() == 2 && MI.getOperand(0).isReg() &&
          MI.getOperand(1).isImm()) {
        REAnalysis.dumpRegTableAfterMI(&MI);
        unsigned Reg1 = MI.getOperand(0).getReg();
        ASSERT_TRUE(REAnalysis.verifyOverlapsInvalidation(MI, Reg1));
      }
    }
  }
}
} // namespace
