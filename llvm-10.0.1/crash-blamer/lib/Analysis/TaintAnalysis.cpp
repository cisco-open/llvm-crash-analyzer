//===- TaintAnalysis.cpp - Catch the source of a crash --------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/TaintAnalysis.h"
#include "llvm/CodeGen/TargetInstrInfo.h"

using namespace llvm;

#define DEBUG_TYPE "taint-analysis"

crash_blamer::TaintAnalysis::TaintAnalysis() {}

bool crash_blamer::TaintAnalysis::runOnBlameMF(const MachineFunction &MF) {
  // Crash Sequence starts after the MI with the crash-blame flag.
  bool CrashSequenceStarted = false;

  auto TII = MF.getSubtarget().getInstrInfo();

  // Perform backward analysis on the MF.
  for (auto MBBIt = MF.rbegin(); MBBIt != MF.rend(); ++MBBIt) {
    auto &MBB = *MBBIt;
    for (auto MIIt = MBB.rbegin(); MIIt != MBB.rend(); ++MIIt) {
      auto &MI = *MIIt;
      if (MI.getFlag(MachineInstr::CrashStart))
        CrashSequenceStarted = true;

      if (!CrashSequenceStarted)
        continue;

      // TODO: Handle calls other than the one from the backtrace.
      if (MI.isCall())
        continue;

      // We reached the end of the frame.
      if (TII->isPushPop(MI))
        break;

      LLVM_DEBUG(MI.dump(););

      auto DestSrc = TII->getDestAndSrc(MI);
      if (!DestSrc) {
        LLVM_DEBUG(
          llvm::dbgs() << "haven't found dest && source for the MI\n";);
        continue;
      }

      LLVM_DEBUG(
          llvm::dbgs() << "***performing taint analysis on the operands\n";
          llvm::dbgs() << "dest: ";
          DestSrc->Destination->dump();
          if (DestSrc->DestOffset)
            llvm::dbgs() << "dest offset: " << DestSrc->DestOffset << "\n";
          llvm::dbgs() << "src: ";
          DestSrc->Source->dump();
          if (DestSrc->SrcOffset)
            llvm::dbgs() << "src offset: " << DestSrc->SrcOffset << "\n";);

      // TODO: Perform the actual analysis here.
    }
  }

  return false;
}

// TODO: Based on the reason of the crash (e.g. signal or error code) read from
// the core file, perform different types of analysis. At the moment, we are
// looking for an instruction that has coused a read from null address.
bool crash_blamer::TaintAnalysis::runOnBlameModule(const BlameModule &BM) {
  llvm::outs() << "\nPerforming Taint Analysis...\n";
  bool AnalysisStarted = false;

  // Run the analysis on each blame function.
  for (auto &BF : BM) {
    // Skip the libc functions for now, if we haven't started the analysis yet.
    // e.g.: _start() and __libc_start_main().
    if (!AnalysisStarted && BF.Name.startswith("_")) {
      LLVM_DEBUG(llvm::dbgs() << "### Skip: " << BF.Name << "\n";);
      continue;
    }

    AnalysisStarted = true;
    // If we have found a MF that we hadn't decompiled (to LLVM MIR), stop
    // the analysis there, since it is a situation where a frame is missing.
    if (!BF.MF) {
      LLVM_DEBUG(llvm::dbgs() << "### Empty MF: " << BF.Name << "\n";);
      llvm::outs() << "Taint Analysis done.\n";
      return false;
    }

    LLVM_DEBUG(llvm::dbgs() << "### MF: " << BF.Name << "\n";);
    if (runOnBlameMF(*(BF.MF)))
      break;
  }

  llvm::outs() << "Taint Analysis done.\n";
  return false;
}
