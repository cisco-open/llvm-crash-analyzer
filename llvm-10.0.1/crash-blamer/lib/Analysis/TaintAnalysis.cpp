//===- TaintAnalysis.cpp - Catch the source of a crash --------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/TaintAnalysis.h"
#include "Analysis/MachineLocTracking.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/IR/DebugInfoMetadata.h"

#include <sstream>

using namespace llvm;

#define DEBUG_TYPE "taint-analysis"

using TaintInfo = llvm::crash_blamer::TaintInfo;

bool llvm::crash_blamer::operator==(const TaintInfo &T1, const TaintInfo &T2) {
  // Consider reg and offset only, since we disabled
  // concrete mem addr calculation.
  if (T1.Op->getReg() == T2.Op->getReg()) {
    if (!T1.Offset && !T2.Offset) {
      return true;
    } else if (!T1.Offset) {
      if (*T2.Offset == 0) {
        return true;
      }
    } else if (!T2.Offset) {
      if (*T1.Offset == 0) {
        return true;
      }
    } else if (T1.Offset && T2.Offset)
      return *T1.Offset == *T2.Offset;
  }

  return false;
}

bool llvm::crash_blamer::operator!=(const TaintInfo &T1, const TaintInfo &T2) {
  return !operator==(T1, T2);
}

crash_blamer::TaintAnalysis::TaintAnalysis() {}

void crash_blamer::TaintAnalysis::calculateMemAddr(TaintInfo &Ti) {
  // This is temporary disabled until Concrete Reverse Execution
  // is completely implemented.
  return;
}

void crash_blamer::TaintAnalysis::mergeTaintList(
    SmallVectorImpl<TaintInfo> &Dest_TL, SmallVectorImpl<TaintInfo> &Src_TL) {
  for (auto itr = Src_TL.begin(); itr != Src_TL.end(); ++itr) {
    // Add TaintInfo to Dest if already not present
    if (isTainted(*itr, Dest_TL).Op == nullptr)
      addToTaintList(*itr, Dest_TL);
    printTaintList(Dest_TL);
  }
}

// Reinitialize the global TaintList with the given input Taintlist
void crash_blamer::TaintAnalysis::resetTaintList(
    SmallVectorImpl<TaintInfo> &TL) {
  // clear the global TaintList
  TaintList.clear();
  // Reset global TaintList to given input Taintlist
  for (auto itr = TL.begin(); itr != TL.end(); ++itr) {
    addToTaintList(*itr, TaintList);
  }
  printTaintList(TL);
}

void crash_blamer::TaintAnalysis::addToTaintList(
    TaintInfo &Ti, SmallVectorImpl<TaintInfo> &TaintList) {
  if (!Ti.Op)
    return;
  if (!Ti.Op->isImm())
    TaintList.push_back(Ti);
}

void llvm::crash_blamer::TaintAnalysis::removeFromTaintList(
    TaintInfo &Op, SmallVectorImpl<TaintInfo> &TaintList) {
  for (auto itr = TaintList.begin(); itr != TaintList.end(); ++itr) {
    if (*itr != Op)
      continue;
    TaintList.erase(itr);
    return;
  }
  llvm_unreachable("Operand not in Taint List");
}

TaintInfo
crash_blamer::TaintAnalysis::isTainted(TaintInfo &Op,
                                       SmallVectorImpl<TaintInfo> &TL) {
  TaintInfo Empty_op;
  Empty_op.Op = nullptr;
  Empty_op.Offset = 0;
  for (auto itr = TL.begin(); itr != TL.end(); ++itr) {
    if (*itr == Op)
      return *itr;
  }
  return Empty_op;
}

void crash_blamer::TaintAnalysis::printTaintList(
    SmallVectorImpl<TaintInfo> &TL) {
  if (TL.empty()) {
    LLVM_DEBUG(dbgs() << "Taint List is empty");
    return;
  }
  LLVM_DEBUG(
      dbgs() << "\n-----Taint List Begin------\n"; for (auto itr = TL.begin();
                                                        itr != TL.end();
                                                        ++itr) {
        if (!itr->IsTaintMemAddr()) {
          itr->Op->dump();
          if (itr->Offset)
            dbgs() << "offset: " << *(itr->Offset) << '\n';
        } else
          dbgs() << "mem addr: " << itr->GetTaintMemAddr() << "\n";
      } dbgs() << "\n------Taint List End----\n";);
}

void crash_blamer::TaintAnalysis::printDestSrcInfo(DestSourcePair &DestSrc) {
  LLVM_DEBUG(
      if (DestSrc.Destination) {
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

void crash_blamer::TaintAnalysis::startTaint(DestSourcePair &DS,
                                             SmallVectorImpl<TaintInfo> &TL) {
  TaintInfo SrcTi, DestTi, Src2Ti;

  SrcTi.Op = DS.Source;
  SrcTi.Offset = DS.SrcOffset;

  DestTi.Op = DS.Destination;
  DestTi.Offset = DS.DestOffset;

  Src2Ti.Op = DS.Source2;
  Src2Ti.Offset = DS.Src2Offset;

  // This condition is true only for frame #0 in back trace
  if (TaintList.empty()) {
    // We want to taint destination only if it is a mem operand
    if (DestTi.Op && DestTi.Offset)
      addToTaintList(DestTi, TL);
    if (SrcTi.Op)
      addToTaintList(SrcTi, TL);
    if (Src2Ti.Op)
      addToTaintList(Src2Ti, TL);
    printTaintList(TL);
  } else {
    // frame #1 onwards
    mergeTaintList(TL, TaintList);
    propagateTaint(DS, TL);
  }
}

// Return true if taint is propagated.
// Return false if taint is terminated.
bool llvm::crash_blamer::TaintAnalysis::propagateTaint(
    DestSourcePair &DS, SmallVectorImpl<TaintInfo> &TL) {
  // If empty taint list, we do nothing and we continue to
  // to propagate the taint along the other paths
  if (TL.empty()) {
    LLVM_DEBUG(dbgs() << "\n No taint to propagate");
    return true;
  }

  TaintInfo SrcTi, Src2Ti, DestTi;
  SrcTi.Op = DS.Source;
  SrcTi.Offset = DS.SrcOffset;

  Src2Ti.Op = DS.Source2;
  Src2Ti.Offset = DS.Src2Offset;

  DestTi.Op = DS.Destination;
  DestTi.Offset = DS.DestOffset;

  if (!DestTi.Op)
    return true;

  // Check if Dest is already tainted.
  auto Taint = isTainted(DestTi, TL);

  // If Destination is not tainted, nothing to do, just move on.
  if (Taint.Op == nullptr)
    return true;

  // If Destination Op is tainted, do the following.
  // Add SrcOp to the taint-list.
  // Remove DestOp from the taint-list.
  // If Src is Immediate, we have reached end of taint.
  // DS.Source is 0 for immediate operands.
  // If two Source Ops are present, both should be immediate
  // For e.g., ADD r1, r1, 4 is not a terminating condition.
  // Or if the instruction involves %rip, treat this as a constant.
  bool ConstantFound = false;
  if (DS.Source && DS.Source->isImm()) {
    if (!DS.Source2)
      ConstantFound = true;
    else if (DS.Source2->isImm())
      ConstantFound = true;
  } else if (DS.Source && DS.Source->isReg()) {
    const MachineFunction *MF = DS.Source->getParent()->getMF();
    auto TRI = MF->getSubtarget().getRegisterInfo();
    std::string RegName = TRI->getRegAsmName(DS.Source->getReg()).lower();
    if (RegName == "rip")
      ConstantFound = true;
  }

  if (ConstantFound) {
    // We have reached a terminating condition where
    // dest is tainted and src is a constant operand.
    removeFromTaintList(DestTi, TL);
    LLVM_DEBUG(dbgs() << "\n******** Blame MI is here\n");
    LLVM_DEBUG(DS.Destination->getParent()->dump());
    llvm::outs() << "\nBlame Function is "
                 << DS.Destination->getParent()->getMF()->getName();
    if (DS.Destination->getParent()->getDebugLoc()) {
      llvm::outs() << "\nAt Line Number "
                   << DS.Destination->getParent()->getDebugLoc().getLine();
      llvm::outs() << ", from file "
                   << DS.Destination->getParent()->getDebugLoc()->getFilename();
    } else {
      llvm::outs()
          << "\nWARNING: Please compile with -g to get full line info.";
      llvm::outs() << "\nBlame instruction is ";
      DS.Destination->getParent()->print(llvm::outs());
    }

    return false;
  }

  addToTaintList(SrcTi, TL);
  removeFromTaintList(DestTi, TL);

  printTaintList(TL);
  return true;
}

// Return true if taint is terminated.
// Return false otherwise.
bool crash_blamer::TaintAnalysis::runOnBlameMF(const MachineFunction &MF) {
  // As a first step, run the forward analysis by tracking values
  // in the machine locations.
  MachineLocTracking MLocTracking;
  MLocTracking.run(const_cast<MachineFunction &>(MF));

  // Per function : Map MBB with its Taint List
  DenseMap<const MachineBasicBlock *, SmallVector<TaintInfo, 8>> MBB_TL_Map;
  // Initialize all the MBB with emtpty taint list
  for (const MachineBasicBlock &MBB : MF) {
    SmallVector<TaintInfo, 8> _tmp;
    MBB_TL_Map[&MBB] = _tmp;
  }

  // TODO: Combine the forward analysis with reading of concrete
  // values from core-file for the purpose of reconstructing
  // concrete memory addresses when a base register is not
  // known at the time by going backward.

  // Crash Sequence starts after the MI with the crash-blame flag.
  bool CrashSequenceStarted = false;
  bool Result = false;

  SmallVector<TaintInfo, 8> *CurTL = nullptr;

  auto TII = MF.getSubtarget().getInstrInfo();

  // Perform backward analysis on the MF.

  for (auto MBBIt = po_begin(&MF.front()),
                                              MBBIt_E = po_end(&MF.front());
       MBBIt != MBBIt_E; ++MBBIt) {
    auto MBB = *MBBIt;
    SmallVector<TaintInfo, 8> &TL_Mbb = MBB_TL_Map.find(MBB)->second;
    CurTL = &TL_Mbb;

    // Initialize Taint list for a MBB
    if (CrashSequenceStarted) {
      for (const MachineBasicBlock *Succ : MBB->successors()) {
        mergeTaintList(TL_Mbb, MBB_TL_Map.find(Succ)->second);
      }
      // If Taint List for an MBB is empty, then no need to analyze this MBB
      printTaintList(TL_Mbb);
      if (TL_Mbb.empty())
        continue;
    }

    for (auto MIIt = MBB->rbegin(); MIIt != MBB->rend(); ++MIIt) {
      auto &MI = *MIIt;

      if (MI.getFlag(MachineInstr::CrashStart)) {
        CrashSequenceStarted = true;
        LLVM_DEBUG(MI.dump(););
        auto DestSrc = TII->getDestAndSrc(MI);
        if (!DestSrc) {
          LLVM_DEBUG(llvm::dbgs()
                     << "Crash instruction doesn't have blame operands\n");
          mergeTaintList(TL_Mbb, TaintList);
          continue;
        }
        startTaint(*DestSrc, TL_Mbb);
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
      if (TII->isPushPop(MI)) {
        break;
      }

      auto DestSrc = TII->getDestAndSrc(MI);
      if (!DestSrc) {
        LLVM_DEBUG(llvm::dbgs()
                       << "haven't found dest && source for the MI\n";);
        continue;
      }

      printDestSrcInfo(*DestSrc);

      // Backward Taint Analysis.
      bool TaintResult = propagateTaint(*DestSrc, TL_Mbb);
      if (!TaintResult)
        Result = true;
    }
  }
  resetTaintList(*CurTL);
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
      Result = Result || true;
      if (TaintList.empty())
        return true;
    }
  }
  // Currently we report SUCCESS even if one Blame Function is found.
  // Ideally SUCCESS is only when TaintList.empty() is true.
  return Result;
}
