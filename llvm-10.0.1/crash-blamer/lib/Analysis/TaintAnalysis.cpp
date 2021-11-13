//===- TaintAnalysis.cpp - Catch the source of a crash --------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/TaintAnalysis.h"
#include "Analysis/RegisterEquivalence.h"
#include "Decompiler/Decompiler.h"
#include "Analysis/ConcreteReverseExec.h"
#include "Analysis/TaintDataFlowGraph.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/IR/DebugInfoMetadata.h"

#include <sstream>

static cl::opt<std::string>
DumpTaintGraphAsDOT("print-dfg-as-dot",
                     cl::desc("Print Tainted graph for the GraphViz."),
                     cl::value_desc("filename"),
                     cl::init(""));

using namespace llvm;

#define DEBUG_TYPE "taint-analysis"

using TaintInfo = llvm::crash_blamer::TaintInfo;

unsigned Node::NextID = 0;

bool llvm::crash_blamer::operator==(const TaintInfo &T1, const TaintInfo &T2) {
  const MachineFunction *MF = T1.Op->getParent()->getMF();
  auto TRI = MF->getSubtarget().getRegisterInfo();
  if (!T1.IsTaintMemAddr() && !T2.IsTaintMemAddr()) {
    // Both operands needs to be reg operands
    if (!T1.Op->isReg() || !T2.Op->isReg())
      return false;

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
  }

  // For mem taint ops, compare the actuall addresses.
  if (T1.IsTaintMemAddr() && T2.IsTaintMemAddr())
    // Here we should be comparing addresses if both available only.
    return T1.GetTaintMemAddr() == T2.GetTaintMemAddr();

  if (!T1.Op->isReg() || !T2.Op->isReg())
    return false;

  // Here we check mem addr base and reg.
  // e.g.: $rsp + 0 == $rsp
  // TODO: Should we check the offset is 0 here?
  if (T1.Op->getReg() == T2.Op->getReg()) {
    if (!T1.Offset && T2.Offset) {
      return *T2.Offset == 0;
    }
    if (!T2.Offset && T1.Offset) {
      return *T1.Offset == 0;
    }
    return *T1.Offset == *T2.Offset;
  }

  // $noreg case
  if (!T1.Op->getReg() || !T2.Op->getReg())
    return false;

  // Check for register aliases.
  for (MCRegAliasIterator RAI(T1.Op->getReg(), TRI, true); RAI.isValid();
       ++RAI) {
    if ((*RAI).id() == T2.Op->getReg()) {
      if (!T1.Offset && T2.Offset) {
        return *T2.Offset == 0;
      }
      if (!T2.Offset && T1.Offset) {
        return *T1.Offset == 0;
      }
      return *T1.Offset == *T2.Offset;
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
  if (!Ti.Op->isReg() || !Ti.Offset)
    return;

  // For registers other than RSP and RBP, without ConcreteRevExec,
  // we cannot be sure if the reg value has changed from the point
  // of the crash.
  const MachineFunction *MF = Ti.Op->getParent()->getMF();
  auto TRI = MF->getSubtarget().getRegisterInfo();
  std::string RegName = TRI->getRegAsmName(Ti.Op->getReg()).lower();

  Ti.IsConcreteMemory = true;

  // $noreg + offset means that the address is the offset itself.
  if (Ti.Op->getReg() == 0) {
    Ti.ConcreteMemoryAddress = *Ti.Offset;
    return;
  }

  // Calculate real address by reading the context of regInfo MF attr
  // (read from corefile).
  std::string RegValue = MF->getRegValueFromCrash(RegName);

  // If the value is not available just taint the base-reg.
  if(RegValue == "") {
    Ti.IsConcreteMemory = false;
    return;
  }

  // Convert the std::string hex number into uint64_t.
  uint64_t RealAddr = 0;
  std::stringstream SS;
  SS << std::hex << RegValue;
  SS >> RealAddr;

  // Apply the offset.
  RealAddr += *Ti.Offset;

  Ti.ConcreteMemoryAddress = RealAddr;
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

bool crash_blamer::TaintAnalysis::addToTaintList(
    TaintInfo &Ti, SmallVectorImpl<TaintInfo> &TaintList) {
  if (!Ti.Op)
    return false;

  for (auto itr = TaintList.begin(); itr != TaintList.end(); ++itr)
    if (Ti == *itr)
      return false;

  if (!Ti.Op->isImm()) {
    TaintList.push_back(Ti);
    return true;
  }
  return false;
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

// Return true if rax register, that stores the return value
// of a function call is present in the taint list.
// Also, if a global variable is tainted, we are interested
// in analyzing the function.
bool
crash_blamer::TaintAnalysis::shouldAnalyzeCall(SmallVectorImpl<TaintInfo> &TL) {
  for (auto itr = TL.begin(); itr != TL.end(); ++itr) {
    const MachineOperand* Op = itr->Op;
    if (!Op->isReg())
      return false;
    const MachineFunction *MF = Op->getParent()->getMF();
    auto TRI = MF->getSubtarget().getRegisterInfo();
    std::string RegName = TRI->getRegAsmName(Op->getReg()).lower();
    if (RegName == "rax" || RegName == "eax" || RegName == "ax" || RegName == "al")
      return true;
    // If a global variable is tainted also return true.
    // (If operand is noreg and non-zero offset).
    if (!Op->getReg() && itr->Offset)
	  return true;
  }
  return false;
}

TaintInfo
crash_blamer::TaintAnalysis::isTainted(TaintInfo &Op,
                                       SmallVectorImpl<TaintInfo> &TL,
                                       RegisterEquivalence *REAnalysis,
                                       const MachineInstr *MI) {
  TaintInfo Empty_op;
  Empty_op.Op = nullptr;
  Empty_op.Offset = 0;

  unsigned OffsetOp = 0;
  if (Op.Offset)
    OffsetOp = *Op.Offset;

  for (auto itr = TL.begin(); itr != TL.end(); ++itr) {
    if (*itr == Op)
      return *itr;
    else if (REAnalysis) {
      if (itr->Op->isReg() && Op.Op->isReg() &&
        Op.Op->getReg() != itr->Op->getReg() &&
        MI != &*MI->getParent()->begin()) {
         unsigned OffsetCurrOp = 0;
         if (itr->Offset)
           OffsetCurrOp = *itr->Offset;
         if (REAnalysis->isEquvalent(
           *const_cast<MachineInstr*>(&*std::prev(MI->getIterator())),
           {itr->Op->getReg(), OffsetCurrOp}, {Op.Op->getReg(), OffsetOp}))
           return *itr;
      }
    }
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
        itr->Op->dump();
        if (itr->Offset)
          dbgs() << "offset: " << *(itr->Offset);
        if (itr->IsTaintMemAddr())
          dbgs() << "(mem addr: " << itr->GetTaintMemAddr() << ")";
        dbgs() << '\n';
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

bool crash_blamer::TaintAnalysis::getIsCrashBlamerTATool() const {
  return isCrashBlamerTATool;
}

void
crash_blamer::TaintAnalysis::setDecompiler(crash_blamer::Decompiler *D) {
  Dec = D;
}
Decompiler *crash_blamer::TaintAnalysis::getDecompiler() const {
  return Dec;
}

void crash_blamer::TaintAnalysis::startTaint(DestSourcePair &DS,
                                             SmallVectorImpl<TaintInfo> &TL,
                                             const MachineInstr &MI,
                                             TaintDataFlowGraph &TaintDFG,
                                             RegisterEquivalence &REAnalysis) {
  TaintInfo SrcTi, DestTi, Src2Ti, SrcScaleReg;

  SrcTi.Op = DS.Source;
  SrcTi.Offset = DS.SrcOffset;
  if (SrcTi.Offset)
    calculateMemAddr(SrcTi);

  SrcScaleReg.Op = DS.SrcScaledIndex;

  DestTi.Op = DS.Destination;
  DestTi.Offset = DS.DestOffset;
  if (DestTi.Offset)
    calculateMemAddr(DestTi);

  Src2Ti.Op = DS.Source2;
  Src2Ti.Offset = DS.Src2Offset;
  if (Src2Ti.Offset)
    calculateMemAddr(Src2Ti);

  // This condition is true only for frame #0 in back trace
  if (TaintList.empty()) {
    Node *cNode = new Node (0, nullptr, DestTi, true);
    std::shared_ptr<Node> crashNode (cNode);
    const auto &MF = MI.getParent()->getParent();
    // We want to taint destination only if it is a mem operand
    if (DestTi.Op && DestTi.Offset && DestTi.Op->isReg()) {
      if (addToTaintList(DestTi, TL)) {
        Node *sNode = new Node(MF->getCrashOrder(), &MI, DestTi, false);
        std::shared_ptr<Node> startTaintNode(sNode);
        TaintDFG.addEdge(crashNode, startTaintNode, EdgeType::Dereference);
        TaintDFG.updateLastTaintedNode(DestTi, startTaintNode);
      }
    }

    // FIXME: This should be checking if src is a mem op somehow,
    // by checking if src2 is an index register.
    if (SrcTi.Op && SrcTi.Op->isReg()) {
      if (addToTaintList(SrcTi, TL)) {
        Node *sNode2 = new Node(MF->getCrashOrder(), &MI, SrcTi, false);
        std::shared_ptr<Node> startTaintNode(sNode2);
        TaintDFG.addEdge(crashNode, startTaintNode, EdgeType::Dereference);
        TaintDFG.updateLastTaintedNode(SrcTi, startTaintNode);
      }
    }

    // If this was memory operand, we should taint the base reg as well.
    if (SrcTi.Op && SrcTi.Op->isReg() && SrcTi.Offset) {
      TaintInfo JustRegFromSrcOp = SrcTi;
      JustRegFromSrcOp.Offset = llvm::None;
      JustRegFromSrcOp.IsConcreteMemory = false;
      JustRegFromSrcOp.ConcreteMemoryAddress = 0;
      if (addToTaintList(JustRegFromSrcOp, TL)) {
        Node *sNode2 = new Node(MF->getCrashOrder(), &MI, JustRegFromSrcOp, false);
        std::shared_ptr<Node> startTaintNode(sNode2);
        TaintDFG.addEdge(crashNode, startTaintNode, EdgeType::Dereference);
        TaintDFG.updateLastTaintedNode(JustRegFromSrcOp, startTaintNode);
      }
    }

    // Taint src scale index reg.
    if (SrcScaleReg.Op && SrcScaleReg.Op->isReg()) {
      if (addToTaintList(SrcScaleReg, TL)) {
        Node *sNode2 = new Node(MF->getCrashOrder(), &MI, SrcScaleReg, false);
        std::shared_ptr<Node> startTaintNode(sNode2);
        TaintDFG.addEdge(crashNode, startTaintNode, EdgeType::Dereference);
        TaintDFG.updateLastTaintedNode(SrcScaleReg, startTaintNode);
      }
    }

    if (Src2Ti.Op && Src2Ti.Op->isReg()) {
      if (addToTaintList(Src2Ti, TL)) {
        Node *sNode3 = new Node(MF->getCrashOrder(), &MI, Src2Ti, false);
        std::shared_ptr<Node> startTaintNode(sNode3);
        TaintDFG.addEdge(crashNode, startTaintNode, EdgeType::Dereference);
        TaintDFG.updateLastTaintedNode(Src2Ti, startTaintNode);
      }
    }
  } else {
    // frame #1 onwards
    mergeTaintList(TL, TaintList);
    propagateTaint(DS, TL, MI, TaintDFG, REAnalysis);
  }
  printTaintList(TL);
}

// Return true if taint is propagated.
// Return false if taint is terminated.
bool llvm::crash_blamer::TaintAnalysis::propagateTaint(
    DestSourcePair &DS, SmallVectorImpl<TaintInfo> &TL,
    const MachineInstr &MI, TaintDataFlowGraph &TaintDFG,
    RegisterEquivalence &REAnalysis,
    const MachineInstr* CallMI) {
  // If empty taint list, we do nothing and we continue to
  // to propagate the taint along the other paths
  if (TL.empty()) {
    LLVM_DEBUG(dbgs() << "\n No taint to propagate");
    return true;
  }

  TaintInfo SrcTi, Src2Ti, DestTi;
  SrcTi.Op = DS.Source;
  SrcTi.Offset = DS.SrcOffset;
  if (SrcTi.Offset)
    calculateMemAddr(SrcTi);

  Src2Ti.Op = DS.Source2;
  Src2Ti.Offset = DS.Src2Offset;
  // FIXME: Here to calculateMemAddr????

  DestTi.Op = DS.Destination;
  DestTi.Offset = DS.DestOffset;
  if (DestTi.Offset)
    calculateMemAddr(DestTi);

  if (!DestTi.Op)
    return true;

  // Check if Dest is already tainted.
  auto Taint = isTainted(DestTi, TL, &REAnalysis, &MI);

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
    // FIXME: Improve this code.
    // This will be used to indentify call instruction when analyzing fns out of
    // bt.
    if (CallMI)
      constantNode->CallMI = CallMI;
    std::shared_ptr<Node> constNode(constantNode);
    auto &LastTaintedNodeForTheOp = TaintDFG.lastTaintedNode[Taint];
    TaintDFG.addEdge(LastTaintedNodeForTheOp, constNode, EdgeType::Dereference);
    // FIXME: The LastTaintedNode won't be used any more, no need for this line?
    TaintDFG.updateLastTaintedNode(SrcTi, constNode);

    // We have reached a terminating condition where
    // dest is tainted and src is a constant operand.
    removeFromTaintList(Taint, TL);

    if (DS.ImmValue) {
    // Start tracking the constant as it can be an address which can be
    // written into later.
    TaintInfo NewTaint;
    static MachineOperand MO = MachineOperand::CreateReg(0U, false);
    MO.setParent(const_cast<MachineInstr*>(&MI));
    NewTaint.Op = &MO;
    NewTaint.IsConcreteMemory = true;
    NewTaint.Offset = *(DS.ImmValue);
    // Assigning int64_t to uint64_t ?
    NewTaint.ConcreteMemoryAddress = *(DS.ImmValue);
    if (addToTaintList(NewTaint, TL)) {
      Node *newNode = new Node(MF->getCrashOrder(), &MI, NewTaint, false);
      std::shared_ptr<Node> newTaintNode(newNode);
      auto &LastTaintedNodeForTheOp = TaintDFG.lastTaintedNode[Taint];
      TaintDFG.addEdge(LastTaintedNodeForTheOp, newTaintNode, EdgeType::Assigment);
      TaintDFG.updateLastTaintedNode(NewTaint, newTaintNode);
      LLVM_DEBUG(dbgs() << "New constant node added \n");
      printTaintList(TL);
    }
   }
    return true;
  }

  if (addToTaintList(SrcTi, TL)) {
    Node *newNode = new Node(MF->getCrashOrder(), &MI, SrcTi, false);
    if (CallMI)
      newNode->CallMI = CallMI;
    std::shared_ptr<Node> newTaintNode(newNode);
    // TODO: Check if this should be a deref edge:
    //       if we propagate taint from a mem addr (e.g. rbx + 10)
    //       to its base reg (e.g. rbx).
    assert(TaintDFG.lastTaintedNode.count(Taint) &&
           "Taint Op must be reached already");
    auto &LastTaintedNodeForTheOp = TaintDFG.lastTaintedNode[Taint];

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

    removeFromTaintList(Taint, TL);
  }

  printTaintList(TL);
  return true;
}

// Return true if taint is terminated.
// Return false otherwise.
bool crash_blamer::TaintAnalysis::runOnBlameMF(const BlameModule &BM,
                                               const MachineFunction &MF,
                                               TaintDataFlowGraph &TaintDFG,
                                               bool CalleeNotInBT,
                                               SmallVector<TaintInfo, 8> *TL_Of_Caller,
                                               const MachineInstr* CallMI) {
  LLVM_DEBUG(llvm::dbgs() << "### MF: " << MF.getName() << "\n";);

  // Run the forward analysis to compute register equivalance.
  RegisterEquivalence REAnalysis;
  REAnalysis.init(const_cast<MachineFunction &>(MF));
  REAnalysis.run(const_cast<MachineFunction &>(MF));

  // Init the concrete reverse execution.
  ConcreteReverseExec ReverseExecutionRecord(&MF);
  ReverseExecutionRecord.dump();

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
        // If this was a call to a function that isn't in the bt,
        // the analysis will start from the last intr (return), so
        // we need just to consider the taint operands from the MBB
        // where it got called.
        if (CalleeNotInBT) {
          mergeTaintList(TL_Mbb, *TL_Of_Caller);
          continue;
        }

        // For frames > 0, skip to the first instruction after the call
        // instruction, traversing backwards.
        // Sometimes analysis starts at some frame != 1, due to some inlined fns
        // preceding that fn.
        if ((MF.getCrashOrder() > 1 && MF.getCrashOrder() != analysisStartedAt)
            || CalleeNotInBT) {
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
        // Analyze the call only if return value is tainted.
	    // TODO: Handling of function parameters that are tainted
        // within the function.
        if (MI2.isCall()) {
          mergeTaintList(TL_Mbb, TaintList);
          const MachineOperand &CalleeOp = MI2.getOperand(0);
          // TODO: handle indirect calls.
          if (!CalleeOp.isGlobal())
            continue;
          auto TargetName = CalleeOp.getGlobal()->getName();
	      if (!shouldAnalyzeCall(TL_Mbb)) {
	       LLVM_DEBUG(llvm::dbgs() << "Not Analyzing function "
                                   << TargetName << "\n");
	       continue;
	      }
          if (CalleeOp.isGlobal()) {
            MachineFunction *CalledMF = getCalledMF(BM, TargetName);
            if (CalledMF) {
              LLVM_DEBUG(llvm::dbgs()
                             << "#### Processing callee " << TargetName << "\n";);
              CalledMF->setCrashOrder(MF.getCrashOrder());
              runOnBlameMF(BM, *CalledMF, TaintDFG, true, &TL_Mbb, &MI2);
              CalledMF->setCrashOrder(0);
              continue;
            } else {
              if (!getIsCrashBlamerTATool()) {
                MachineFunction *MFOnDemand = Dec->decompileOnDemand(TargetName);
                if (!MFOnDemand) {
                  LLVM_DEBUG(llvm::dbgs()
                             << "#### Callee not found: " << TargetName << "\n";);
                  continue;
                } else {
                  MFOnDemand->setCrashOrder(MF.getCrashOrder());
                  runOnBlameMF(BM, *MFOnDemand, TaintDFG, true, &TL_Mbb, &MI);
                  MFOnDemand->setCrashOrder(0);
                }
              } else {
                LLVM_DEBUG(
                  llvm::dbgs()
                      << "#### Callee not found: " << TargetName << "\n";);
                continue;
              }
            }
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
        startTaint(*DestSrc, TL_Mbb, MI2, TaintDFG, REAnalysis);
        continue;
      }

      if (!CrashSequenceStarted)
        continue;

      // Update the register values, so we have right regiter values state.
      ReverseExecutionRecord.execute(MI);

      // Process call instruction that is not in backtrace
      // Analyze the call only if return value is tainted.
      // TBD: We ignore tainted parameters since we do not have a good
      // way to identify machine operands that are function parameters.
      if (MI.isCall()) {
      //  mergeTaintList(TL_Mbb, TaintList); Is this needed (as above) ?
        const MachineOperand &CalleeOp = MI.getOperand(0);
        // TODO: handle indirect calls.
        if (!CalleeOp.isGlobal())
          continue;

        auto TargetName = CalleeOp.getGlobal()->getName();
	    if (!shouldAnalyzeCall(TL_Mbb)) {
	      LLVM_DEBUG(llvm::dbgs() << "Not Analyzing function "
                                  << TargetName << "\n");
          continue;
	    }
        MachineFunction *CalledMF = getCalledMF(BM, TargetName);
        if (CalledMF) {
          CalledMF->setCrashOrder(MF.getCrashOrder());
          runOnBlameMF(BM, *CalledMF, TaintDFG, true, &TL_Mbb, &MI);
          CalledMF->setCrashOrder(0);
          continue;
        } else {
          if (!getIsCrashBlamerTATool()) {
            MachineFunction *MFOnDemand = Dec->decompileOnDemand(TargetName);
            if (!MFOnDemand) {
              LLVM_DEBUG(llvm::dbgs()
                         << "#### Callee not found: " << TargetName << "\n";);
              continue;
            } else {
              // Handle it.
              MFOnDemand->setCrashOrder(MF.getCrashOrder());
              runOnBlameMF(BM, *MFOnDemand, TaintDFG, true, &TL_Mbb, &MI);
              MFOnDemand->setCrashOrder(0);
            }
          } else {
            LLVM_DEBUG(
              llvm::dbgs()
                  << "#### Callee not found: " << TargetName << "\n";);
            continue;
          }
        }
      }

      if (MI.isBranch())
        continue;

      // Print the instruction from crash-start point
      LLVM_DEBUG(MI.dump(););

      // We reached the end of the frame.
      if (TII->isPush(MI))
        break;

      auto DestSrc = TII->getDestAndSrc(MI);
      if (!DestSrc) {
        LLVM_DEBUG(llvm::dbgs()
                       << "haven't found dest && source for the MI\n";);
        continue;
      }

      printDestSrcInfo(*DestSrc);

      // Backward Taint Analysis.
      bool TaintResult = propagateTaint(*DestSrc, TL_Mbb, MI, TaintDFG, REAnalysis,
                                        CallMI);
      if (!TaintResult)
        Result = true;
    }
  }
  resetTaintList(*CurTL);
  return Result;
}

// Dummy MFs of our inlined frames have dummy NOOP instruction only.
static bool isInline(MachineFunction* MF) {
  if (MF->size() != 1)
    return false;

  auto &MBB = MF->front();
  if (MBB.size() != 1)
    return false;

  auto TII = MF->getSubtarget().getInstrInfo();
  auto &Inst = MBB.instr_front();
  if (TII->isNoopInstr(Inst))
    return true;

  return false;
}

// TODO: Based on the reason of the crash (e.g. signal or error code) read from
// the core file, perform different types of analysis. At the moment, we are
// looking for an instruction that has coused a read from null address.
bool crash_blamer::TaintAnalysis::runOnBlameModule(const BlameModule &BM) {
  bool AnalysisStarted = false;
  bool Result = false;

  llvm::outs() << "\nAnalyzing...\n";

  TaintDataFlowGraph TaintDFG;

  // Run the analysis on each blame function.
  for (auto &BF : BM) {
    // Skip the libc functions for now, if we haven't started the analysis yet.
    // e.g.: _start() and __libc_start_main().
    if (!AnalysisStarted && BF.Name.startswith("_")) {
      LLVM_DEBUG(llvm::dbgs() << "### Skip: " << BF.Name << "\n";);
      ++analysisStartedAt;
      continue;
    }
    if (!AnalysisStarted && !BF.MF->getCrashOrder()) {
      LLVM_DEBUG(llvm::dbgs() << "### Skip: " << BF.Name << "\n";);
      ++analysisStartedAt;
      continue;
    }

    if (!AnalysisStarted && isInline(BF.MF)) {
      LLVM_DEBUG(llvm::dbgs() << "### Skip inline fn: " << BF.Name << "\n";);
      ++analysisStartedAt;
      continue;
    }

    AnalysisStarted = true;
    // If we have found a MF that we hadn't decompiled (to LLVM MIR), stop
    // the analysis there, since it is a situation where a frame is missing.
    if (!BF.MF) {
      LLVM_DEBUG(llvm::dbgs() << "### Empty MF: " << BF.Name << "\n";);
      return Result;
    }

    if (runOnBlameMF(BM, *(BF.MF), TaintDFG, false)) {
      LLVM_DEBUG(dbgs() << "\nTaint Analysis done.\n");
      if (TaintList.empty()) {
        if (DumpTaintGraphAsDOT != "") {
          StringRef file_name = DumpTaintGraphAsDOT;
          if (!file_name.endswith(".dot") && !file_name.endswith(".gv"))
            errs() << "error: DOT file must be with '.dot' or '.gv' extension.\n";
          else
           TaintDFG.printAsDOT(file_name.str());
        }
        TaintDFG.dump();
        if (!TaintDFG.getBlameNodesSize()) {
          llvm::outs() << "\nNo blame function found.\n";
          return false;
        }

        auto crashNode = TaintDFG.getCrashNode();
        TaintDFG.findBlameFunction(crashNode);
        Result = TaintDFG.printBlameFunction();
        return Result;
      }
    }
  }

  if (DumpTaintGraphAsDOT != "") {
    StringRef file_name = DumpTaintGraphAsDOT;
    if (!file_name.endswith(".dot") && !file_name.endswith(".gv"))
      errs() << "error: DOT file must be with '.dot' or '.gv' extension.\n";
    else
      TaintDFG.printAsDOT(file_name.str());
  }

  TaintDFG.dump();
  if (!TaintDFG.getBlameNodesSize()) {
    llvm::outs() << "\nNo blame function found.\n";
    return false;
  }

  auto crashNode = TaintDFG.getCrashNode();
  TaintDFG.findBlameFunction(crashNode);
  Result = TaintDFG.printBlameFunction();

  // Currently we report SUCCESS even if one Blame Function is found.
  // Ideally SUCCESS is only when TaintList.empty() is true.
  return Result;
}
