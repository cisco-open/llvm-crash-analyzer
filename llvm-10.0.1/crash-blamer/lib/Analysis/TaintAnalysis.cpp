//===- TaintAnalysis.cpp - Catch the source of a crash --------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/TaintAnalysis.h"

using namespace llvm;

#define DEBUG_TYPE "taint-analysis"

using TaintInfo = llvm::crash_blamer::TaintInfo;

bool llvm::crash_blamer::operator==(const TaintInfo &T1, const TaintInfo &T2) {
  if (!T1.Op->isReg() || !T2.Op->isReg())
    return false;

  if (T1.Op->getReg() != T2.Op->getReg())
    return false;

  if (T1.Offset != T2.Offset)
    return false;

  return true;
}

bool llvm::crash_blamer::operator!=(const TaintInfo &T1, const TaintInfo &T2) {
  if (!T1.Op->isReg() || !T2.Op->isReg())
    return true;

  if (T1.Op->getReg() == T2.Op->getReg()) {
    if (T1.Offset == T2.Offset)
      return false;
  }

  return true;
}

crash_blamer::TaintAnalysis::TaintAnalysis() {}

void crash_blamer::TaintAnalysis::addToTaintList(TaintInfo &Ti) {
  if (!Ti.Op)
    return;
  if (!Ti.Op->isImm()) {
    TaintList.push_back(Ti);
  }
}

void llvm::crash_blamer::TaintAnalysis::removeFromTaintList(TaintInfo &Op) {
  for (auto itr = TaintList.begin(); itr != TaintList.end(); ++itr) {
    if (*itr != Op)
      continue;
    TaintList.erase(itr);
    return;
  }
  llvm_unreachable("Operand not in Taint List");
}

TaintInfo crash_blamer::TaintAnalysis::isTainted(TaintInfo &Op) {
  TaintInfo Empty_op;
  Empty_op.Op = nullptr;
  Empty_op.Offset = 0;
  for (auto itr = TaintList.begin(); itr != TaintList.end(); ++itr) {
    if (*itr == Op)
      return *itr;
  }
  return Empty_op;
}

void crash_blamer::TaintAnalysis::printTaintList() {
  if (TaintList.empty()) {
    LLVM_DEBUG(dbgs() << "Taint List is empty");
    return;
  }
  LLVM_DEBUG(dbgs() << "\n-----Taint List Begin------\n";
             for (auto itr = TaintList.begin(); itr != TaintList.end(); ++itr) {
               itr->Op->dump();
               dbgs() << "Offset =  " << itr->Offset << "\n";
             } dbgs()
             << "\n------Taint List End----\n";);
}

void crash_blamer::TaintAnalysis::printDestSrcInfo(DestSourcePair &DestSrc) {

  LLVM_DEBUG(if (DestSrc.Destination) {
    llvm::dbgs() << "dest: ";
    DestSrc.Destination->dump();
    if (DestSrc.DestOffset)
      llvm::dbgs() << "dest offset: " << DestSrc.DestOffset << "\n";
  } if (DestSrc.Source) {
    llvm::dbgs() << "src: ";
    DestSrc.Source->dump();
    if (DestSrc.SrcOffset)
      llvm::dbgs() << "src offset: " << DestSrc.SrcOffset << "\n";
  } if (DestSrc.Source2) {
    llvm::dbgs() << "src2: ";
    DestSrc.Source2->dump();
    if (DestSrc.Src2Offset)
      llvm::dbgs() << "src2 offset: " << DestSrc.Src2Offset << "\n";
  });
}

void crash_blamer::TaintAnalysis::startTaint(DestSourcePair &DS) {
  // This is the case when analysis begins.
  TaintInfo SrcTi, DestTi, Src2Ti;
  SrcTi.Op = DS.Source;
  SrcTi.Offset = DS.SrcOffset;
  DestTi.Op = DS.Destination;
  DestTi.Offset = DS.DestOffset;
  Src2Ti.Op = DS.Source2;
  Src2Ti.Offset = DS.Src2Offset;

  if (TaintList.empty()) {
    if (SrcTi.Op)
      addToTaintList(SrcTi);
    if (DestTi.Op)
      addToTaintList(DestTi);
    if (Src2Ti.Op)
      addToTaintList(Src2Ti);
    printTaintList();
  } else
      // For Frames > 1.
      if (DestTi.Op)
    propagateTaint(DS);
}

// Return true if taint is propagated.
// Return false if taint is terminated.
bool llvm::crash_blamer::TaintAnalysis::propagateTaint(DestSourcePair &DS) {
  // Terminating condition 1.
  // This can happen only due to lack of info/data for some taints.
  if (TaintList.empty()) {
    LLVM_DEBUG(dbgs() << "\n No taint to propagate");
    return false;
  }

  TaintInfo SrcTi, DestTi;
  SrcTi.Op = DS.Source;
  SrcTi.Offset = DS.SrcOffset;
  DestTi.Op = DS.Destination;
  DestTi.Offset = DS.DestOffset;

  if (!DestTi.Op)
    return true;

  // Check if Dest is already tainted.
  auto Taint = isTainted(DestTi);
  if (Taint.Op != nullptr) {
    // Add SrcOp to the taint-list.
    // Remove DestOp from the taint-list.
    // If Src is Immediate, we have reached end of taint.
    // DS.Source is 0 for immediate operands.
    if (DS.Source->isImm()) {
      // We have reached a terminating condition where
      // dest is tainted and src is a constant operand.
      removeFromTaintList(DestTi);
      LLVM_DEBUG(dbgs() << "\n******** Blame MI is here\n");
      LLVM_DEBUG(DS.Destination->getParent()->dump());
      llvm::outs() << "\nBlame Function is "
                   << DS.Destination->getParent()->getMF()->getName();
      llvm::outs() << "\nAt Line Number "
                   << DS.Destination->getParent()->getDebugLoc().getLine();
      return false;
    }
    addToTaintList(SrcTi);
    removeFromTaintList(DestTi);
  }

  printTaintList();
  return true;
}

// Return true if taint is terminated.
// Return false otherwise.
bool crash_blamer::TaintAnalysis::runOnBlameMF(const MachineFunction &MF) {
  // Crash Sequence starts after the MI with the crash-blame flag.
  bool CrashSequenceStarted = false;
  bool Result = false;

  auto TII = MF.getSubtarget().getInstrInfo();

  // Perform backward analysis on the MF.
  for (auto MBBIt = MF.rbegin(); MBBIt != MF.rend(); ++MBBIt) {
    auto &MBB = *MBBIt;
    for (auto MIIt = MBB.rbegin(); MIIt != MBB.rend(); ++MIIt) {
      auto &MI = *MIIt;
      if (MI.getFlag(MachineInstr::CrashStart)) {
        CrashSequenceStarted = true;
        LLVM_DEBUG(MI.dump(););
        auto DestSrc = TII->getDestAndSrc(MI);
        if (!DestSrc) {
          llvm::outs() << "Crash instruction doesn't have blame operands\n";
          continue;
        }
        printDestSrcInfo(*DestSrc);
        startTaint(*DestSrc);
        continue;
      }

      if (!CrashSequenceStarted)
        continue;

      // TBD : If Call Instruction, we may have to analyze the call
      // if it modifies a tainted operand.
      if (MI.isCall() || MI.isBranch())
        continue;

      // Print the instruction from crash-start point
      LLVM_DEBUG(MI.dump(););

      // We reached the end of the frame.
      if (TII->isPushPop(MI))
        break;

      auto DestSrc = TII->getDestAndSrc(MI);
      if (!DestSrc) {
        LLVM_DEBUG(llvm::dbgs()
                       << "haven't found dest && source for the MI\n";);
        continue;
      }

      printDestSrcInfo(*DestSrc);

      // Backward Taint Analysis.
      bool TaintResult = propagateTaint(*DestSrc);
      if (!TaintResult)
        Result = true;
      if (!TaintResult && TaintList.empty()) {
        LLVM_DEBUG(dbgs() << "\n Taint Terminated");
        return true;
      }
    }
  }

  return Result;
}

// TODO: Based on the reason of the crash (e.g. signal or error code) read from
// the core file, perform different types of analysis. At the moment, we are
// looking for an instruction that has coused a read from null address.
bool crash_blamer::TaintAnalysis::runOnBlameModule(const BlameModule &BM) {
  bool AnalysisStarted = false;
  bool Result = false;

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
      return Result;
    }

    LLVM_DEBUG(llvm::dbgs() << "### MF: " << BF.Name << "\n";);
    if (runOnBlameMF(*(BF.MF))) {
      LLVM_DEBUG(dbgs() << "\nTaint Analysis done.\n");
      Result = Result | true;
      if (TaintList.empty())
        return true;
    }
  }
  // Currently we report SUCCESS even if one Blame Function is found.
  // Ideally SUCCESS is only when TaintList.empty() is true.
  return Result;
}
