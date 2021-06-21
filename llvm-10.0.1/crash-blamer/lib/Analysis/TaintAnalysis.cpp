//===- TaintAnalysis.cpp - Catch the source of a crash --------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/TaintAnalysis.h"
#include "Analysis/TaintDataFlowGraph.h"
#include "Analysis/MachineLocTracking.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/IR/DebugInfoMetadata.h"

#include <sstream>

using namespace llvm;

#define DEBUG_TYPE "taint-analysis"

using TaintInfo = llvm::crash_blamer::TaintInfo;

unsigned Node::NextID = 0;

bool llvm::crash_blamer::operator==(const TaintInfo &T1, const TaintInfo &T2) {
  // Consider reg and offset only, since we disabled
  // concrete mem addr calculation.

  // Both operands needs to be reg operands
  if (!T1.Op->isReg() || !T2.Op->isReg())
    return false;

  const MachineFunction *MF = T1.Op->getParent()->getMF();
  auto TRI = MF->getSubtarget().getRegisterInfo();
  if (T1.Op->getReg() == T2.Op->getReg()) {
    // Check if both operands have an offset
    if (T1.Offset && T2.Offset) {
      std::string RegName = TRI->getRegAsmName(T1.Op->getReg()).lower();
      // Compare offsets only if they point to a stack location
      if (RegName == "rsp" || RegName == "rbp") {
        return *T1.Offset == *T2.Offset;
      }
    } else
      return true;
  }

  // Check for noreg case.
  // Check offsets if both operands are noreg
  if (!T1.Op->getReg() && !T2.Op->getReg()) {
    if (T1.Offset && T2.Offset)
      return *T1.Offset == *T2.Offset;
  }

  if (!T1.Op->getReg() || !T2.Op->getReg())
    return false;

  // Check if the registers are alias to each other
  // eax and rax, for example
  for (MCRegAliasIterator RAI(T1.Op->getReg(), TRI, true); RAI.isValid();
       ++RAI) {
    if ((*RAI).id() == T2.Op->getReg()) {
      return true;
    }
  }
  return false;
}

bool llvm::crash_blamer::operator!=(const TaintInfo &T1, const TaintInfo &T2) {
  return !operator==(T1, T2);
}

bool llvm::crash_blamer::operator<(const TaintInfo &T1, const TaintInfo &T2) {
  if (T1.Op->isReg() && T2.Op->isReg()) {
    if (T1.Op->getReg() && T2.Op->getReg()) {
    // Check if the registers are alias to each other
    // eax and rax, for example
    const MachineFunction *MF = T1.Op->getParent()->getMF();
    auto TRI = MF->getSubtarget().getRegisterInfo();
    for (MCRegAliasIterator RAI(T1.Op->getReg(), TRI, true); RAI.isValid();
         ++RAI) {
      if ((*RAI).id() == T2.Op->getReg()) {
        return false;
      }
    }
    if (T1.Op->getReg() < T2.Op->getReg())
      return true;
    }
    // Check for noreg
    if (!T1.Op->getReg() && !T2.Op->getReg()) {
      if (T1.Offset && T2.Offset)
        return *T1.Offset < *T2.Offset;
    }
  }
  return false;
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

MachineFunction* crash_blamer::TaintAnalysis::getCalledMF(const BlameModule &BM, std::string Name) {
  for (auto &BF : BM) {
     std::pair<llvm::StringRef, llvm::StringRef> match  = BF.Name.split('.');
    if (Name == match.first)
     return BF.MF;
  }
  return nullptr;
}

void crash_blamer::TaintAnalysis::startTaint(DestSourcePair &DS,
                                             SmallVectorImpl<TaintInfo> &TL,
                                             const MachineInstr &MI,
                                             TaintDataFlowGraph &TaintDFG) {
  TaintInfo SrcTi, DestTi, Src2Ti, SrcScaleReg;

  SrcTi.Op = DS.Source;
  SrcTi.Offset = DS.SrcOffset;

  SrcScaleReg.Op = DS.SrcScaledIndex;

  DestTi.Op = DS.Destination;
  DestTi.Offset = DS.DestOffset;

  Src2Ti.Op = DS.Source2;
  Src2Ti.Offset = DS.Src2Offset;

  // This condition is true only for frame #0 in back trace
  if (TaintList.empty()) {
    Node *cNode = new Node (0, nullptr, DestTi, true);
    std::shared_ptr<Node> crashNode (cNode);
    const auto &MF = MI.getParent()->getParent();
    // We want to taint destination only if it is a mem operand
    if (DestTi.Op && DestTi.Offset && DestTi.Op->isReg()) {
      Node *sNode = new Node(MF->getCrashOrder(), &MI, DestTi, false);
      std::shared_ptr<Node> startTaintNode(sNode);
      TaintDFG.addEdge(crashNode, startTaintNode, EdgeType::Dereference);
      TaintDFG.updateLastTaintedNode(DestTi, startTaintNode);
      addToTaintList(DestTi, TL);
    }

    // FIXME: This should be checking if src is a mem op somehow,
    // by checking if src2 is an index register.
    if (SrcTi.Op && SrcTi.Op->isReg()) {
      Node *sNode2 = new Node(MF->getCrashOrder(), &MI, SrcTi, false);
      std::shared_ptr<Node> startTaintNode(sNode2);
      TaintDFG.addEdge(crashNode, startTaintNode, EdgeType::Dereference);
      TaintDFG.updateLastTaintedNode(SrcTi, startTaintNode);
      addToTaintList(SrcTi, TL);
    }

    // Taint src scale index reg.
    if (SrcScaleReg.Op && SrcScaleReg.Op->isReg()) {
      Node *sNode2 = new Node(MF->getCrashOrder(), &MI, SrcScaleReg, false);
      std::shared_ptr<Node> startTaintNode(sNode2);
      TaintDFG.addEdge(crashNode, startTaintNode, EdgeType::Dereference);
      TaintDFG.updateLastTaintedNode(SrcScaleReg, startTaintNode);
      addToTaintList(SrcScaleReg, TL);
    }

    if (Src2Ti.Op && Src2Ti.Op->isReg()) {
      Node *sNode3 = new Node(MF->getCrashOrder(), &MI, Src2Ti, false);
      std::shared_ptr<Node> startTaintNode(sNode3);
      TaintDFG.addEdge(crashNode, startTaintNode, EdgeType::Dereference);
      TaintDFG.updateLastTaintedNode(Src2Ti, startTaintNode);
      addToTaintList(Src2Ti, TL);
    }
  } else {
    // frame #1 onwards
    mergeTaintList(TL, TaintList);
    propagateTaint(DS, TL, MI, TaintDFG);
  }
  printTaintList(TL);
}

// Return true if taint is propagated.
// Return false if taint is terminated.
bool llvm::crash_blamer::TaintAnalysis::propagateTaint(
    DestSourcePair &DS, SmallVectorImpl<TaintInfo> &TL,
    const MachineInstr &MI, TaintDataFlowGraph &TaintDFG) {
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

  const auto &MF = MI.getParent()->getParent();
  auto TII = MF->getSubtarget().getInstrInfo();

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
  } else if (TII->isXORSimplifiedSetToZero(MI)) {
    // xor eax, eax is the same as move eax, 0
    ConstantFound = true;
  }

  if (ConstantFound) {
    Node *constantNode = new Node(MF->getCrashOrder(), &MI, SrcTi, false, true);
    std::shared_ptr<Node> constNode(constantNode);
    auto &LastTaintedNodeForTheOp = TaintDFG.lastTaintedNode[DestTi];
    TaintDFG.addEdge(LastTaintedNodeForTheOp, constNode, EdgeType::Dereference);
    // FIXME: The LastTaintedNode won't be used any more, no need for this line?
    TaintDFG.updateLastTaintedNode(SrcTi, constNode);

    // We have reached a terminating condition where
    // dest is tainted and src is a constant operand.
    removeFromTaintList(DestTi, TL);
    return false;
  }

  addToTaintList(SrcTi, TL);

  Node *newNode = new Node(MF->getCrashOrder(), &MI, SrcTi, false);
  std::shared_ptr<Node> newTaintNode(newNode);
  // TODO: Check if this should be a deref edge:
  //       if we propagate taint from a mem addr (e.g. rbx + 10)
  //       to its base reg (e.g. rbx).
  assert(TaintDFG.lastTaintedNode.count(DestTi) &&
         "Taint Op must be reached already");
  auto &LastTaintedNodeForTheOp = TaintDFG.lastTaintedNode[DestTi];

  if(LastTaintedNodeForTheOp->TaintOp.Op->isReg() &&
     LastTaintedNodeForTheOp->TaintOp.Offset &&
     newTaintNode->TaintOp.Op->isReg() &&
     (LastTaintedNodeForTheOp->TaintOp.Op->getReg() ==
      newTaintNode->TaintOp.Op->getReg()))
    TaintDFG.addEdge(LastTaintedNodeForTheOp, newTaintNode,
                     EdgeType::Dereference);
  else
    TaintDFG.addEdge(LastTaintedNodeForTheOp, newTaintNode);
  TaintDFG.updateLastTaintedNode(SrcTi, newTaintNode);

  removeFromTaintList(DestTi, TL);

  printTaintList(TL);
  return true;
}

// Return true if taint is terminated.
// Return false otherwise.
bool crash_blamer::TaintAnalysis::runOnBlameMF(const BlameModule &BM,
                                               const MachineFunction &MF,
                                               TaintDataFlowGraph &TaintDFG,
                                               bool CalleeNotInBT) {
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

  for (auto MBBIt = po_begin(&MF.front()), MBBIt_E = po_end(&MF.front());
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
        // For frames > 0, skip to the first instruction after the call
        // instruction, traversing backwards
        if (MF.getCrashOrder() > 1 || CalleeNotInBT) {
          if (!CalleeNotInBT) {
            // Skip processing crash instruction
            ++MIIt;
            if (MIIt == MBB->rend())
              return Result;
          }
          // Skip processing the call instruction
          ++MIIt;
          if (MIIt == MBB->rend())
            return Result;
        }
        auto &MI2 = *MIIt;
        // Process the call instruction that is not in the backtrace
        if (MI2.isCall()) {
          const MachineOperand &CalleeOp = MI2.getOperand(0);
          // TODO: handle indirect calls.
          if (!CalleeOp.isGlobal())
            continue;
          auto TargetName = CalleeOp.getGlobal()->getName();
          if (CalleeOp.isGlobal()) {
            MachineFunction *CalledMF = getCalledMF(BM, TargetName);
            if (CalledMF) {
              LLVM_DEBUG(llvm::dbgs()
                             << "#### Processing callee " << TargetName << "\n";);
              CalledMF->setCrashOrder(MF.getCrashOrder());
              runOnBlameMF(BM, *CalledMF, TaintDFG, true);
              CalledMF->setCrashOrder(0);
              continue;
            } else
              LLVM_DEBUG(llvm::dbgs()
                             << "#### Callee not found: " << TargetName << "\n";);
          }
        }
        auto DestSrc = TII->getDestAndSrc(MI2);
        if (!DestSrc) {
          LLVM_DEBUG(llvm::dbgs()
                     << "Crash instruction doesn't have blame operands\n";
	  MI2.dump(););
          mergeTaintList(TL_Mbb, TaintList);
          continue;
        }
        startTaint(*DestSrc, TL_Mbb, MI2, TaintDFG);
        continue;
      }

      if (!CrashSequenceStarted)
        continue;
      // Process call instruction that is not in backtrace
      // TODO: Currently we process *all* call instructions. Is this necessary ?
      if (MI.isCall()) {
        const MachineOperand &CalleeOp = MI.getOperand(0);
        // TODO: handle indirect calls.
        if (!CalleeOp.isGlobal())
          continue;
        auto TargetName = CalleeOp.getGlobal()->getName();
        MachineFunction *CalledMF = getCalledMF(BM, TargetName);
        if (CalledMF) {
          CalledMF->setCrashOrder(MF.getCrashOrder());
          runOnBlameMF(BM, *CalledMF, TaintDFG, true);
          CalledMF->setCrashOrder(0);
          continue;
        } else
          LLVM_DEBUG(llvm::dbgs()
                         << "#### func not found: " << TargetName << "\n";);
      }

      if (MI.isBranch()) {
        continue;
      }

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
      bool TaintResult = propagateTaint(*DestSrc, TL_Mbb, MI, TaintDFG);
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

  TaintDataFlowGraph TaintDFG;

  // Run the analysis on each blame function.
  for (auto &BF : BM) {
    // Skip the libc functions for now, if we haven't started the analysis yet.
    // e.g.: _start() and __libc_start_main().
    if (!AnalysisStarted && BF.Name.startswith("_")) {
      LLVM_DEBUG(llvm::dbgs() << "### Skip: " << BF.Name << "\n";);
      continue;
    }
    if (!BF.MF->getCrashOrder()) {
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

    LLVM_DEBUG(llvm::dbgs() << "### MF: " << BF.Name << " " << BF.MF->getCrashOrder() << " \n";);
    if (runOnBlameMF(BM, *(BF.MF), TaintDFG, false)) {

      LLVM_DEBUG(dbgs() << "\nTaint Analysis done.\n");
      if (TaintList.empty()) {
        TaintDFG.dump();
        if (!TaintDFG.getBlameNodesSize()) {
          llvm::outs() << "\nNo blame function found.\n";
          return false;
        }

        auto crashNode = TaintDFG.getCrashNode();
        TaintDFG.findBlameFunction(crashNode, 0);
        Result = TaintDFG.printBlameFunction();
        return Result;
      }
    }
  }

  TaintDFG.dump();
  if (!TaintDFG.getBlameNodesSize()) {
    llvm::outs() << "\nNo blame function found.\n";
    return false;
  }

  auto crashNode = TaintDFG.getCrashNode();
  TaintDFG.findBlameFunction(crashNode, 0);
  Result = TaintDFG.printBlameFunction();

  // Currently we report SUCCESS even if one Blame Function is found.
  // Ideally SUCCESS is only when TaintList.empty() is true.
  return Result;
}
