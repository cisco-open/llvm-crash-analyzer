//===- TaintAnalysis.cpp - Catch the source of a crash --------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/TaintAnalysis.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/CodeGen/TargetInstrInfo.h"

using namespace llvm;

#define DEBUG_TYPE "taint-analysis"

// Tainted Operands in a Machine Instruction.
// This is a Reg-Offset pair.
struct TaintInfo {
  const MachineOperand *op;
  int64_t Offset;
};

bool operator==(const TaintInfo &t1, const TaintInfo &t2) {
  if (t1.op->isReg() && t2.op->isReg()) {
    if (t1.op->getReg() == t2.op->getReg()) {
      if (t1.Offset == t2.Offset)
        return true;
      else
        return false;
    }
  }
  return false;
}

bool operator!=(const TaintInfo &t1, const TaintInfo &t2) {
  if (t1.op->isReg() && t2.op->isReg()) {
    if (t1.op->getReg() != t2.op->getReg()) {
      if (t1.Offset != t2.Offset)
        return true;
      else
        return false;
    }
  }
  return false;
}

SmallVector<TaintInfo, 8> TaintList;

crash_blamer::TaintAnalysis::TaintAnalysis() {}

bool propagateTaint(DestSourcePair &ds);
void startTaint(DestSourcePair &ds);

void addToTaintList(TaintInfo &ti) {
  if (!ti.op)
    return;
  if (!ti.op->isImm())
    TaintList.push_back(ti);
  return;
}

void removeFromTaintList(TaintInfo &op) {
  for (auto itr = TaintList.begin(); itr != TaintList.end(); ++itr) {
    if (*itr != op)
      continue;
    TaintList.erase(itr);
    return;
  }
}

TaintInfo isTainted(TaintInfo &op) {
  TaintInfo empty_op;
  empty_op.op = nullptr;
  empty_op.Offset = 0;
  for (auto itr = TaintList.begin(); itr != TaintList.end(); ++itr) {
    if (*itr == op)
      return *itr;
  }
  return empty_op;
}

void printTaintList(void) {
  if (TaintList.empty()) {
    LLVM_DEBUG(dbgs() << "Taint List is empty");
    return;
  }
  LLVM_DEBUG(dbgs() << "\n-----Taint List Begin------\n");
  LLVM_DEBUG(for (auto itr = TaintList.begin(); itr != TaintList.end(); ++itr) {
    itr->op->dump();
    dbgs() << "Offset =  " << itr->Offset;
  });
  LLVM_DEBUG(dbgs() << "\n------Taint List End----\n");
}

void startTaint(DestSourcePair &ds) {
  // This is the case when analysis begins

  TaintInfo src_ti, dst_ti;

  src_ti.op = ds.Source;
  src_ti.Offset = ds.SrcOffset;

  dst_ti.op = ds.Destination;
  dst_ti.Offset = ds.DestOffset;

  if (TaintList.empty()) {
    addToTaintList(src_ti);
    addToTaintList(dst_ti);
    printTaintList();
    return;
  } else // For Frames > 1
    propagateTaint(ds);

  return;
}

// Return true if taint is propagated
// Return false if taint is terminated
bool propagateTaint(DestSourcePair &ds) {
  // Terminating condition 1
  // This can happen only due to lack of info/data for some taints
  if (TaintList.empty()) {
    LLVM_DEBUG(dbgs() << "\n No taint to propagate");
    return false;
  }

  TaintInfo src_ti;
  TaintInfo dest_ti;

  src_ti.op = ds.Source;
  src_ti.Offset = ds.SrcOffset;
  dest_ti.op = ds.Destination;
  dest_ti.Offset = ds.DestOffset;

  // Check if Dest is already tainted
  auto taint = isTainted(dest_ti);
  if (taint.op != nullptr) {
    // Add SrcOp to the taint-list
    // Remove DestOp from the taint-list
    // If Src is Immediate, we have reached end of taint
    // ds.Source is 0 for immediate operands
    if (ds.Source->isImm()) {
      // We have reached a terminating condition where
      // dest is tainted and src is a constant operand
      removeFromTaintList(dest_ti);
      LLVM_DEBUG(dbgs() << "\n******** Blame MI is here\n");
      LLVM_DEBUG(ds.Destination->getParent()->dump());
      llvm::outs() << "\nBlame Function is "
                   << ds.Destination->getParent()->getMF()->getName();
      llvm::outs() << "\nAt Line Number "
                   << ds.Destination->getParent()->getDebugLoc().getLine();
      return false;
    }
    addToTaintList(src_ti);
    removeFromTaintList(dest_ti);
  }

  printTaintList();
  return true;
}

/* Return true if taint is terminated
 * Return false otherwise
 */
bool crash_blamer::TaintAnalysis::runOnBlameMF(const MachineFunction &MF) {
  // Crash Sequence starts after the MI with the crash-blame flag.
  bool CrashSequenceStarted = false;

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
        startTaint(*DestSrc);
        continue;
      }

      if (!CrashSequenceStarted)
        continue;

      /* TBD : If Call Instruction, we may have to analyze the call
       * if it modifies a tainted operand
       */
      if (MI.isCall())
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

      LLVM_DEBUG(llvm::dbgs() << "dest: "; DestSrc->Destination->dump();
                 if (DestSrc->DestOffset) llvm::dbgs()
                 << "dest offset: " << DestSrc->DestOffset << "\n";
                 llvm::dbgs() << "src: "; DestSrc->Source->dump();
                 if (DestSrc->SrcOffset) llvm::dbgs()
                 << "src offset: " << DestSrc->SrcOffset << "\n";);

      // Backward Taint Analysis
      if (!propagateTaint(*DestSrc) && TaintList.empty()) {
        LLVM_DEBUG(dbgs() << "\n Taint Terminated");
        return true;
      }
    }
  }

  return false;
}

// TODO: Based on the reason of the crash (e.g. signal or error code) read from
// the core file, perform different types of analysis. At the moment, we are
// looking for an instruction that has coused a read from null address.
bool crash_blamer::TaintAnalysis::runOnBlameModule(const BlameModule &BM) {
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
      return false;
    }

    LLVM_DEBUG(llvm::dbgs() << "### MF: " << BF.Name << "\n";);
    if (runOnBlameMF(*(BF.MF))) {
      LLVM_DEBUG(dbgs() << "\nTaint Analysis done.\n");
      return true;
    }
  }

  return false;
}
