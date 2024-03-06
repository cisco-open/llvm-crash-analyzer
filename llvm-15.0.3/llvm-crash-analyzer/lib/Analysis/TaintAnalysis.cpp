//===- TaintAnalysis.cpp - Catch the source of a crash --------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/TaintAnalysis.h"
#include "Analysis/ConcreteReverseExec.h"
#include "Analysis/RegisterEquivalence.h"
#include "Analysis/TaintDataFlowGraph.h"
#include "Decompiler/Decompiler.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Support/Debug.h"
#include <sstream>

static constexpr unsigned FrameLevelDepthToGo = 10;
static bool abortAnalysis = false;

static cl::opt<bool> PrintDestSrcOperands(
    "print-dest-src-operands",
    cl::desc("Print Destination and Source Operands for each MIR"),
    cl::init(false));

// For development purpose, it is possible to explicitly set location, from
// which we should start Taint Analysis.
// Use -start-taint-reg to specify location register (simple register location
// or memory location base register).
static cl::opt<std::string>
    StartTaintReg("start-taint-reg",
                  cl::desc("Explicitlly set start Taint Info register."),
                  cl::value_desc("start_reg"), cl::init(""));
// Use -start-taint-offset to specify offset to the memory location.
static cl::opt<std::string>
    StartTaintOff("start-taint-offset",
                  cl::desc("Explicitlly set start Taint Info offset."),
                  cl::value_desc("start_off"), cl::init(""));
// Use -start-taint-deref-lvl to specify deref level to the memory location.
static cl::opt<std::string>
    StartTaintDerefLevel("start-taint-deref-lvl",
                  cl::desc("Explicitlly set start Taint Info deref level."),
                  cl::value_desc("start_deref_lvl"), cl::init(""));
// Use -start-crash-order to specify crash order of the function, from which
// we should start Taint Analysis.
static cl::opt<unsigned>
    StartCrashOrder("start-crash-order",
                    cl::desc("Set frame to start tracking target taint info."),
                    cl::value_desc("start_crash_order"), cl::init(0));

using namespace llvm;

#define DEBUG_TYPE "taint-analysis"

using TaintInfo = llvm::crash_analyzer::TaintInfo;

unsigned Node::NextID = 0;

// New implementation of operator==.
bool llvm::crash_analyzer::operator==(const TaintInfo &T1,
                                      const TaintInfo &T2) {
  // Compare immediate values.
  if (T1.Op->isImm() && T2.Op->isImm())
    return T1.Op->getImm() == T2.Op->getImm();

  // Both operands needs to be reg operands.
  if (!T1.Op->isReg() || !T2.Op->isReg())
    return false;

  const MachineFunction *MF = T1.Op->getParent()->getMF();
  auto TRI = MF->getSubtarget().getRegisterInfo();
  // Check if register operands match, including $noreg case.
  bool RegsMatch = T1.Op->getReg() == T2.Op->getReg();
  // Check if the registers are aliases to each other eax and rax, for example.
  if (T1.Op->getReg() && T2.Op->getReg()) {
    for (MCRegAliasIterator RAI(T1.Op->getReg(), TRI, true); RAI.isValid();
         ++RAI) {
      if ((*RAI).id() == T2.Op->getReg()) {
        RegsMatch = true;
      }
    }
  }

  // Both are memory locations.
  if (T1.Offset && T2.Offset) {
    // Both have ConcreteMemoryAddress calculated.
    if (T1.IsTaintMemAddr() && T2.IsTaintMemAddr())
      // Here we compare addresses if both available only.
      return T1.GetTaintMemAddr() == T2.GetTaintMemAddr();

    // Consider cases where ConcreteMemoryAddress is not calculated.
    if (RegsMatch)
      // Both Regs and Offsets need to match.
      return *T1.Offset == *T2.Offset;

    return false;
  }

  // Both are simple register locations.
  if (!T1.Offset && !T2.Offset)
    // Just regsiters need to match.
    return RegsMatch;

  // Consider cases where one TaintInfo is memory location and other is
  // register. If one has offset zero and other doesn't have offset, consider
  // them the same. ex. rax == rax + 0 or eax = rax + 0
  uint64_t Off = T1.Offset ? *T1.Offset : *T2.Offset;
  if (Off == 0)
    // Just registers need to match.
    return RegsMatch;

  return false;
}

bool llvm::crash_analyzer::operator!=(const TaintInfo &T1,
                                      const TaintInfo &T2) {
  return !operator==(T1, T2);
}

// Convert TaintInfo to a tuple which contains the following fields:
// 1. TaintInfoType - ImmediateVal = 0, RegisterLoc = 1, MemoryLoc = 2;
// 2. RegisterID - Register ID (from TargetInfo) or -1 for $noreg;
// 3. IntegerValue - Value of Immediate or Offset of Memory Location.
std::tuple<unsigned, int, int>
llvm::crash_analyzer::TaintInfo::getTuple() const {
  // For Immediate TI type, just set IntegerValue of the tuple.
  if (Op->isImm())
    return {TaintInfoType::ImmediateVal, 0, Op->getImm()};

  assert(Op->isReg() && "TaintInfo operand is either Immediate or Register");
  // Get register ID from TargetInfo. For $noreg it will be -1.
  int RegOpID = -1;
  if (Op->getReg()) {
    auto CATI = getCATargetInfoInstance();
    const MachineFunction *MF = Op->getParent()->getMF();
    auto TRI = MF->getSubtarget().getRegisterInfo();
    std::string RegName = TRI->getRegAsmName(Op->getReg()).lower();
    // For register operand get ID.
    assert(CATI->getID(RegName) && "We should be able to get Regsiter Op ID");
    RegOpID = *CATI->getID(RegName);
  }
  // If there is no offset, TI is a Register, so just set the register ID.
  if (!Offset)
    return {TaintInfoType::RegisterLoc, RegOpID, 0};

  int Off = *Offset;
  // For Memory locations, set ID of the Base Register and Offset as well.
  return {TaintInfoType::MemoryLoc, RegOpID, Off};
}

bool llvm::crash_analyzer::TaintInfo::isTargetStartTaint(
    unsigned CrashOrder) const {
  if (StartCrashOrder != CrashOrder)
    return false;
  auto Tup1 = getTuple();
  std::tuple<unsigned, int, int> Tup2;
  // Get target TaintInfo register.
  int RegOpID = -1;
  if (StartTaintReg != "") {
    auto CATI = getCATargetInfoInstance();
    // Get register ID.
    if (!CATI->getID(StartTaintReg))
      return false;
    RegOpID = *CATI->getID(StartTaintReg);
  }
  if (StartTaintOff == "") {
    Tup2 = {TaintInfoType::RegisterLoc, RegOpID, 0};
    return Tup1 == Tup2;
  }
  // Get target TaintInfo offset.
  int Off = std::stoi(StartTaintOff);
  Tup2 = {TaintInfoType::MemoryLoc, RegOpID, Off};
  return Tup1 == Tup2;
}

// New implementation of the operator<. Based on the tuple representation of
// TaintInfo.
bool llvm::crash_analyzer::operator<(const TaintInfo &T1, const TaintInfo &T2) {
  auto Tup1 = T1.getTuple();
  auto Tup2 = T2.getTuple();
  if (std::get<0>(Tup1) == std::get<0>(Tup2)) {
    if (std::get<1>(Tup1) == std::get<1>(Tup2)) {
      return std::get<2>(Tup1) < std::get<2>(Tup2);
    }
    return std::get<1>(Tup1) < std::get<1>(Tup2);
  }
  return std::get<0>(Tup1) < std::get<0>(Tup2);
}

raw_ostream &llvm::crash_analyzer::operator<<(raw_ostream &os,
                                              const TaintInfo &T) {
  if (T.Op) {
    if (T.Op->isReg()) {
      os << "{reg:" << *T.Op;
      if (T.Offset)
        os << "; off:" << T.Offset;
      os << "}";
      if (T.IsTaintMemAddr())
        os << " (mem addr: " << T.GetTaintMemAddr() << ")";
    } else if (T.Op->isImm())
      os << "{imm:" << *T.Op << "}";
  }
  os << "[deref-level: " << T.DerefLevel << "]";
  return os;
}

// Store and Load instructions change Dereference level of Tainted location,
// starting from the crash point.
void crash_analyzer::TaintInfo::propagateDerefLevel(const MachineInstr &MI) {
  const auto &MF = MI.getParent()->getParent();
  auto TII = MF->getSubtarget().getInstrInfo();
  if (TII->isStore(MI))
    ++DerefLevel;
  else if (TII->isLoad(MI))
    --DerefLevel;
}

crash_analyzer::TaintAnalysis::TaintAnalysis(
    StringRef TaintDotFileName, StringRef MirDotFileName,
    bool PrintPotentialCrashCauseLocation)
    : TaintDotFileName(TaintDotFileName), MirDotFileName(MirDotFileName),
      PrintPotentialCrashCauseLocation(PrintPotentialCrashCauseLocation) {}

void crash_analyzer::TaintAnalysis::calculateMemAddr(TaintInfo &Ti) {
  if (!Ti.Op->isReg() || !Ti.Offset)
    return;

  // For registers other than RSP and RBP, without ConcreteRevExec,
  // we cannot be sure if the reg value has changed from the point
  // of the crash.
  auto MI = Ti.Op->getParent();
  const MachineFunction *MF = MI->getMF();
  auto TRI = MF->getSubtarget().getRegisterInfo();
  std::string RegName = TRI->getRegAsmName(Ti.Op->getReg()).lower();

  Ti.IsConcreteMemory = true;

  // $noreg + offset means that the address is the offset itself.
  if (Ti.Op->getReg() == 0) {
    Ti.ConcreteMemoryAddress = *Ti.Offset;
    return;
  }

  auto *CurrentCRE = getCRE();
  if (!CurrentCRE) {
    Ti.IsConcreteMemory = false;
    return;
  }
  // Calculate real address by reading the context of regInfo MF attr
  // (read from corefile).
  std::string RegValue = CurrentCRE->getCurretValueInReg(RegName);
  auto CATI = getCATargetInfoInstance();
  if (RegValue == "") {
    if (!MI) {
      Ti.IsConcreteMemory = false;
      return;
    }
    // Try to see if there is an equal register that could be used here.
    auto MII = MachineBasicBlock::iterator(const_cast<MachineInstr *>(MI));
    if (MII != MI->getParent()->begin()) {
      if (!REA) {
        Ti.IsConcreteMemory = false;
        return;
      }

      // We try to see what was reg eq. status before the MI.
      MII = std::prev(MII);
      auto EqRegs = REA->getEqRegsAfterMI(const_cast<MachineInstr *>(&*MII),
                                          (unsigned)Ti.Op->getReg());
      if (EqRegs.size() == 0) {
        Ti.IsConcreteMemory = false;
        return;
      }

      for (auto &eqR : EqRegs) {
        uint64_t AddrValue = 0;
        uint64_t Val = 0;
        // Read (base) register value, if it is not $noreg.
        if (eqR.RegNum != 0) {
          std::string rName = TRI->getRegAsmName(eqR.RegNum).lower();
          std::string rValue = CurrentCRE->getCurretValueInReg(rName);
          if (rValue == "")
            continue;

          std::istringstream converter(rValue);
          converter >> std::hex >> AddrValue;
          // If the base register is PC, use address (PC value) of the next MI.
          if (CATI->isPCRegister(RegName)) {
            if (!CATI->getInstAddr(MI))
              continue;
            AddrValue = *CATI->getInstAddr(MI) + *CATI->getInstSize(MI);
          }
          Val = AddrValue;
        }
        // If eqR is register location just add the offset to it, if it is a
        // dereferenced memory location, read the value from memory and add
        // the offset.
        if (eqR.IsDeref) {
          AddrValue += eqR.Offset;
          if (!Dec || !Dec->getTarget())
            break;
          lldb::SBError err;
          Val = Dec->getTarget()->GetProcess().ReadUnsignedFromMemory(AddrValue,
                                                                      8, err);
        }
        Val += *Ti.Offset;
        Ti.ConcreteMemoryAddress = Val;
        return;
      }
    }

    Ti.IsConcreteMemory = false;
    return;
  }

  // Convert the std::string hex number into uint64_t.
  uint64_t RealAddr = 0;
  std::stringstream SS;
  SS << std::hex << RegValue;
  SS >> RealAddr;
  // If the base register is PC, use address (PC value) of the next MI.
  if (CATI->isPCRegister(RegName)) {
    if (!MI || !CATI->getInstAddr(MI)) {
      Ti.IsConcreteMemory = false;
      return;
    }
    RealAddr = *CATI->getInstAddr(MI) + *CATI->getInstSize(MI);
  }

  // Apply the offset.
  RealAddr += *Ti.Offset;

  Ti.ConcreteMemoryAddress = RealAddr;
}

void crash_analyzer::TaintAnalysis::mergeTaintList(
    SmallVectorImpl<TaintInfo> &Dest_TL, SmallVectorImpl<TaintInfo> &Src_TL) {
  for (auto itr = Src_TL.begin(); itr != Src_TL.end(); ++itr) {
    // Add TaintInfo to Dest if already not present
    if (isTainted(*itr, Dest_TL).Op == nullptr)
      addToTaintList(*itr, Dest_TL);
    printTaintList(Dest_TL);
  }
}

// Reinitialize the global TaintList with the given input Taintlist
void crash_analyzer::TaintAnalysis::resetTaintList(
    SmallVectorImpl<TaintInfo> &TL) {
  // clear the global TaintList
  TaintList.clear();
  // Reset global TaintList to given input Taintlist
  for (auto itr = TL.begin(); itr != TL.end(); ++itr) {
    addToTaintList(*itr, TaintList);
  }
  printTaintList(TL);
}

void crash_analyzer::TaintAnalysis::updateTaintDerefLevel(
    TaintInfo &Ti, SmallVectorImpl<TaintInfo> &TaintList,
    const MachineInstr &MI) {
  for (auto itr = TaintList.begin(); itr != TaintList.end(); ++itr)
    if (Ti == *itr) {
      itr->DerefLevel = Ti.DerefLevel;
      itr->propagateDerefLevel(MI);
      LLVM_DEBUG(dbgs() << "Force Update Deref level in Taint List:\n For "
                        << *itr << "\n");
    }
}

bool crash_analyzer::TaintAnalysis::addToTaintList(
    TaintInfo &Ti, SmallVectorImpl<TaintInfo> &TaintList) {
  if (!Ti.Op)
    return false;

  for (auto itr = TaintList.begin(); itr != TaintList.end(); ++itr)
    if (Ti == *itr) {
      if (Ti.DerefLevel != itr->DerefLevel) {
        LLVM_DEBUG(dbgs() << "Update Deref level in Taint List:\n For " << *itr
                          << " use level of " << Ti << "\n");
        itr->DerefLevel = Ti.DerefLevel;
      }
      return false;
    }

  if (!Ti.Op->isImm()) {
    LLVM_DEBUG(dbgs() << "Add to TL: " << Ti << "\n");
    TaintList.push_back(Ti);
    return true;
  }
  return false;
}

void llvm::crash_analyzer::TaintAnalysis::removeFromTaintList(
    TaintInfo &Op, SmallVectorImpl<TaintInfo> &TaintList) {
  for (auto itr = TaintList.begin(); itr != TaintList.end(); ++itr) {
    if (*itr != Op)
      continue;
    LLVM_DEBUG(dbgs() << "Remove from TL: " << Op << "\n");
    TaintList.erase(itr);
    return;
  }
  llvm_unreachable("Operand not in Taint List");
}

// Find the instruction, which loaded parameter value in the register location.
const MachineInstr *crash_analyzer::TaintAnalysis::findParamLoadingInstr(
    TaintInfo &Ti, const MachineInstr *CallMI) {
  MachineInstr *MI = nullptr;
  if (!CallMI)
    return nullptr;
  auto *MBB = CallMI->getParent();
  auto *MF = CallMI->getMF();
  auto TII = MF->getSubtarget().getInstrInfo();
  // Skip the call instruction.
  auto I = std::next(CallMI->getReverseIterator());
  // Search for an instruction, which loads parameter value in register(Ti) in
  // the same MBB.
  for (; I != MBB->rend(); ++I) {
    // We stop the search at the new call site.
    if (I->isCall())
      break;
    auto DestSrc = TII->getDestAndSrc(*I);
    if (!DestSrc)
      continue;

    TaintInfo DestTi;
    DestTi.Op = DestSrc->Destination;
    DestTi.Offset = DestSrc->DestOffset;
    if (DestTi.Offset)
      calculateMemAddr(DestTi);
    // Compare loded value (DestTi) to the register.
    if (DestTi == Ti)
      return &*I;
  }
  return MI;
}

// Return true, if any parameter forwarding register location is tainted.
// Add tainted parameters to the TaintList (TL_Of_Caller), which will be used
// during forward TaintAnalysis of the called function.
bool crash_analyzer::TaintAnalysis::areParamsTainted(
    const MachineInstr *CallMI, SmallVectorImpl<TaintInfo> &TL,
    SmallVectorImpl<TaintInfo> *TL_Of_Caller, TaintDataFlowGraph &TaintDFG,
    RegisterEquivalence &REAnalysis) {
  auto CATI = getCATargetInfoInstance();
  const MachineFunction *MF = CallMI->getMF();

  bool Tainted = false;

  // Search the parameter forwarding registers.
  // TODO: Add support for parameters forwarded via stack.
  auto RegMap = CATI->getWholeRegMap();
  for (auto regTuple : RegMap) {
    std::string LargestRegName = std::get<0>(regTuple.second);
    if (!CATI->isParamFwdRegister(LargestRegName))
      continue;
    // Get unsigned identifier from Reg name.
    auto OptReg = CATI->getRegister(LargestRegName, CallMI);
    unsigned Reg = OptReg ? *OptReg : 0;

    // Create a TaintInfo for param forwarding register.
    TaintInfo Ti;
    MachineOperand MOp = MachineOperand::CreateReg(MCRegister(Reg), false);
    MOp.setParent(const_cast<MachineInstr *>(CallMI));
    Ti.Op = new MachineOperand(MOp);

    // Check if the register (parameter) is tainted.
    auto Taint = isTainted(Ti, TL, &REAnalysis, CallMI);
    if (Taint.Op == nullptr)
      continue;

    // FIXME: Confirm that the param is a reference?
    if (Taint.DerefLevel >= 0)
      continue;

    Tainted = true;

    // FIXME: Should we update deref level for Ti?
    Ti.DerefLevel = Taint.DerefLevel;

    // Add param forwarding reg to the Caller's TL.
    if (addToTaintList(Ti, *TL_Of_Caller)) {
      // For now use CallMI for param forwarding node.
      auto LoadMI = findParamLoadingInstr(Ti, CallMI);
      Node *newNode = new Node(MF->getCrashOrder(), LoadMI, Ti, false);
      if (CallMI)
        newNode->CallMI = CallMI;
      std::shared_ptr<Node> newTaintNode(newNode);
      // TODO: Check if this should be a deref edge:
      //       if we propagate taint from a mem addr (e.g. rbx + 10)
      //       to its base reg (e.g. rbx).
      assert(TaintDFG.lastTaintedNode.count(Taint.Op) &&
             "Taint Op must be reached already");
      auto &LastTaintedNodeForTheOp = TaintDFG.lastTaintedNode[Taint.Op];
      // Set new node depth.
      newTaintNode->Depth = LastTaintedNodeForTheOp->Depth + 1;

      if (LastTaintedNodeForTheOp->TaintOp.Op->isReg() &&
          LastTaintedNodeForTheOp->TaintOp.Offset &&
          newTaintNode->TaintOp.Op->isReg() &&
          (LastTaintedNodeForTheOp->TaintOp.Op->getReg() ==
           newTaintNode->TaintOp.Op->getReg()))
        TaintDFG.addEdge(LastTaintedNodeForTheOp, newTaintNode,
                         EdgeType::Dereference);
      else
        TaintDFG.addEdge(LastTaintedNodeForTheOp, newTaintNode);
      TaintDFG.updateLastTaintedNode(Ti.Op, newTaintNode);
    }
  }

  return Tainted;
}

// Return true if rax register, that stores the return value
// of a function call is present in the taint list.
// Also, if a global variable is tainted, we are interested
// in analyzing the function.
bool crash_analyzer::TaintAnalysis::shouldAnalyzeCall(
    SmallVectorImpl<TaintInfo> &TL) {
  auto CATI = getCATargetInfoInstance();
  for (auto itr = TL.begin(); itr != TL.end(); ++itr) {
    const MachineOperand *Op = itr->Op;
    if (!Op->isReg())
      return false;
    const MachineFunction *MF = Op->getParent()->getMF();
    auto TRI = MF->getSubtarget().getRegisterInfo();
    std::string RegName = TRI->getRegAsmName(Op->getReg()).lower();
    if (CATI->isRetValRegister(RegName))
      return true;
    // If a global variable is tainted also return true.
    // FIXME: Should we check for IsGlobal flag.
    if (!Op->getReg() && itr->Offset)
      return true;
  }
  return false;
}

// Check TaintList for non-dereferenced locations, equivalent to stack slots
// and add those stack locations to the TL_Of_Caller (to be tracked during
// TaintAnalysis of functions out of the backtrace).
bool crash_analyzer::TaintAnalysis::isStackSlotTainted(
    const MachineInstr *CallMI, SmallVectorImpl<TaintInfo> &TL,
    SmallVectorImpl<TaintInfo> *TL_Of_Caller, TaintDataFlowGraph &TaintDFG,
    RegisterEquivalence *REAnalysis) {
  auto *MF = CallMI->getMF();
  auto TRI = MF->getSubtarget().getRegisterInfo();
  auto CATI = getCATargetInfoInstance();

  if (!REAnalysis)
    return false;
  bool Tainted = false;

  // Search for tainted stack slots.
  for (auto itr = TL.begin(); itr != TL.end(); ++itr) {
    auto Taint = *itr;
    // Consider only memory Taint Infos.
    if (!Taint.Op->isReg() || !Taint.Offset)
      continue;

    int64_t OffsetOp = *Taint.Offset;

    if (!CallMI)
      break;
    // Try to see if there is an equal register that could be used here.
    auto MII = MachineBasicBlock::iterator(const_cast<MachineInstr *>(CallMI));
    if (MII == CallMI->getParent()->begin())
      break;

    // We try to see what was reg eq. status before the MI.
    MII = std::prev(MII);
    auto EqRegs = REAnalysis->getEqRegsAfterMI(
        const_cast<MachineInstr *>(&*MII),
        {Taint.Op->getReg(), OffsetOp, /*IsDeref=*/false});

    for (auto &eqR : EqRegs) {
      // Read (base) register value, if it is not $noreg.
      if (eqR.RegNum == 0)
        continue;
      std::string RegName = TRI->getRegAsmName(eqR.RegNum).lower();
      int64_t Offset = eqR.Offset;
      // FIXME: Confirm that the param is a reference?
      if (Taint.DerefLevel >= 0)
        break;

      if (!CATI->isSPRegister(RegName) || !eqR.IsDeref)
        continue;
      // Create a TaintInfo for param forwarding stack slot.
      TaintInfo Ti;
      MachineOperand MOp =
          MachineOperand::CreateReg(MCRegister(eqR.RegNum), false);
      MOp.setParent(const_cast<MachineInstr *>(CallMI));
      Ti.Op = new MachineOperand(MOp);
      Ti.Offset = Offset;
      // Based on the equivalance $rbp+(-40) : { deref->$rsp },
      // Ti ($rsp + 0) has one DerefLevel below ($rbp+(-40)).
      Ti.DerefLevel = Taint.DerefLevel - 1;

      // Add param forwarding memory location to the Caller's TL.
      if (addToTaintList(Ti, *TL_Of_Caller)) {
        Tainted = true;
        // For now, use CallMI for param forwarding node.
        auto LoadMI = findParamLoadingInstr(Ti, CallMI);
        Node *newNode = new Node(MF->getCrashOrder(), LoadMI, Ti, false);
        if (CallMI)
          newNode->CallMI = CallMI;
        std::shared_ptr<Node> newTaintNode(newNode);
        assert(TaintDFG.lastTaintedNode.count(Taint.Op) &&
               "Taint Op must be reached already");
        auto &LastTaintedNodeForTheOp = TaintDFG.lastTaintedNode[Taint.Op];
        // Set new node depth.
        newTaintNode->Depth = LastTaintedNodeForTheOp->Depth + 1;

        if (LastTaintedNodeForTheOp->TaintOp.Op->isReg() &&
            LastTaintedNodeForTheOp->TaintOp.Offset &&
            newTaintNode->TaintOp.Op->isReg() &&
            (LastTaintedNodeForTheOp->TaintOp.Op->getReg() ==
             newTaintNode->TaintOp.Op->getReg()))
          TaintDFG.addEdge(LastTaintedNodeForTheOp, newTaintNode,
                           EdgeType::Dereference);
        else
          TaintDFG.addEdge(LastTaintedNodeForTheOp, newTaintNode);
        TaintDFG.updateLastTaintedNode(Ti.Op, newTaintNode);
      }
    }
  }
  return Tainted;
}

TaintInfo crash_analyzer::TaintAnalysis::isTainted(
    TaintInfo &Op, SmallVectorImpl<TaintInfo> &TL,
    RegisterEquivalence *REAnalysis, const MachineInstr *MI) {
  TaintInfo Empty_op;
  Empty_op.Op = nullptr;
  Empty_op.Offset = 0;

  int64_t OffsetOp = 0;
  if (Op.Offset)
    OffsetOp = *Op.Offset;

  for (auto itr = TL.begin(); itr != TL.end(); ++itr) {
    if (*itr == Op)
      return *itr;
    else if (REAnalysis) {
      if (itr->Op->isReg() && Op.Op->isReg() &&
          Op.Op->getReg() != itr->Op->getReg() &&
          MI != &*MI->getParent()->begin()) {
        int64_t OffsetCurrOp = 0;
        if (itr->Offset)
          OffsetCurrOp = *itr->Offset;
        if (REAnalysis->isEquivalent(
                *const_cast<MachineInstr *>(&*std::prev(MI->getIterator())),
                {itr->Op->getReg(), OffsetCurrOp}, {Op.Op->getReg(), OffsetOp}))
          return *itr;
      }
    }
  }
  return Empty_op;
}

// This function is called when we do not know the source and destination
// operands of a MIR during taint analysis.
// If any of the machine operands in the given MIR is present in the taint
// list, conservatively terminate the analysis.
// Return true if OK to continue Analysis.
// Return false if Analysis needs to be terminated.
bool crash_analyzer::TaintAnalysis::continueAnalysis(
    const MachineInstr &MI, SmallVectorImpl<TaintInfo> &TL,
    RegisterEquivalence &REAnalysis) {
  for (unsigned i = 0; i < MI.getNumOperands(); i++) {
    TaintInfo Ti;
    Ti.Op = &MI.getOperand(i);
    // We can only check if register is in the taint list as we do not have
    // any other information about the specific operands (like reg+offset)
    // or the concrete memory address.
    if (!Ti.Op->isReg())
      continue;
    if (isTainted(Ti, TL, &REAnalysis, &MI).Op != nullptr)
      return false;
  }
  // No tainted operand found in this MIR, so OK to continue Analysis.
  return true;
}

void crash_analyzer::TaintAnalysis::printTaintList(
    SmallVectorImpl<TaintInfo> &TL) {
  if (TL.empty()) {
    LLVM_DEBUG(dbgs() << "Taint List is empty\n");
    return;
  }
  LLVM_DEBUG(dbgs() << "\n-----Taint List Begin------\n";
             for (auto itr = TL.begin(); itr != TL.end(); ++itr) dbgs()
             << *itr << '\n';
             dbgs() << "------Taint List End----\n";);
}

void crash_analyzer::TaintAnalysis::printTaintList2(
    SmallVectorImpl<TaintInfo> &TL) {
  if (TL.empty()) {
    dbgs() << "Taint List is empty";
    return;
  }

  dbgs() << "\n-----Taint List Begin------\n";
  for (auto itr = TL.begin(); itr != TL.end(); ++itr) {
    itr->Op->dump();
    if (itr->Offset)
      dbgs() << "offset: " << *(itr->Offset);
    if (itr->IsTaintMemAddr())
      dbgs() << "(mem addr: " << itr->GetTaintMemAddr() << ")";
    dbgs() << '\n';
  }
  dbgs() << "\n------Taint List End----\n";
}

inline static bool isDebug() {
#ifndef NDEBUG
  return DebugFlag && isCurrentDebugType(DEBUG_TYPE);
#else
  return false;
#endif
}

// Print the destination and source operands info if either of the option
// -print-dest-src-operands or --debug-only=taint-analysis is used.
void crash_analyzer::TaintAnalysis::printDestSrcInfo(DestSourcePair &DestSrc,
                                                     const MachineInstr &MI) {
  if (!PrintDestSrcOperands && !isDebug())
    return;

  const auto &MF = MI.getParent()->getParent();
  auto TRI = MF->getSubtarget().getRegisterInfo();

  llvm::dbgs() << "\n";
  MI.dump();
  if (DestSrc.Destination) {
    llvm::dbgs() << "Dest {reg:"
                 << printReg(DestSrc.Destination->getReg(), TRI);
    if (DestSrc.DestOffset)
      llvm::dbgs() << "; off:" << DestSrc.DestOffset;
    llvm::dbgs() << "}\n";
  }
  if (DestSrc.Source) {
    llvm::dbgs() << "Src1 {";
    if (DestSrc.Source->isReg()) {
      llvm::dbgs() << "reg:" << printReg(DestSrc.Source->getReg(), TRI);
      if (DestSrc.SrcOffset)
        llvm::dbgs() << "; off:" << DestSrc.SrcOffset;
    }
    if (DestSrc.Source->isImm())
      llvm::dbgs() << "imm:" << DestSrc.Source->getImm();
    llvm::dbgs() << "}\n";
  }
  if (DestSrc.Source2) {
    llvm::dbgs() << "Src2 {";
    if (DestSrc.Source2->isReg()) {
      llvm::dbgs() << "reg:" << printReg(DestSrc.Source2->getReg(), TRI);
      if (DestSrc.Src2Offset)
        llvm::dbgs() << "; off:" << DestSrc.Src2Offset;
    }
    if (DestSrc.Source2->isImm())
      llvm::dbgs() << "imm:" << DestSrc.Source2->getImm();
    llvm::dbgs() << "}\n";
  }
  // TODO: Add support for Scaled Index Addressing Mode
}

MachineFunction *
crash_analyzer::TaintAnalysis::getCalledMF(const BlameModule &BM,
                                           std::string Name) {
  for (auto &BF : BM) {
    std::pair<llvm::StringRef, llvm::StringRef> match = BF.Name.split('.');
    if (Name == match.first)
      return BF.MF;
  }
  return nullptr;
}

bool crash_analyzer::TaintAnalysis::getIsCrashAnalyzerTATool() const {
  return isCrashAnalyzerTATool;
}

void crash_analyzer::TaintAnalysis::setDecompiler(
    crash_analyzer::Decompiler *D) {
  Dec = D;
}
Decompiler *crash_analyzer::TaintAnalysis::getDecompiler() const { return Dec; }

void crash_analyzer::TaintAnalysis::insertTaint(
    DestSourcePair &DS, SmallVectorImpl<TaintInfo> &TL, const MachineInstr &MI,
    TaintDataFlowGraph &TaintDFG, RegisterEquivalence &REAnalysis) {
  TaintInfo DestTi;
  DestTi.Op = DS.Destination;
  DestTi.Offset = DS.DestOffset;
  if (DestTi.Offset)
    calculateMemAddr(DestTi);
  if (StartTaintDerefLevel != "")
    DestTi.DerefLevel = std::stoi(StartTaintDerefLevel);

  if (!TL.empty())
    resetTaintList(TL);
  const auto &MF = MI.getParent()->getParent();
  LLVM_DEBUG(dbgs() << "TaintAnalysis::insertTaint\n");
  Node *cNode = new Node(0, nullptr, DestTi, true);
  std::shared_ptr<Node> crashNode(cNode);
  // We want to taint destination only if it is a mem operand
  if (addToTaintList(DestTi, TL)) {
    StartCrashOrder = 0;
    Node *sNode = new Node(MF->getCrashOrder(), &MI, DestTi, false);
    std::shared_ptr<Node> startTaintNode(sNode);
    // Set new node depth (crashNode has zero depth).
    startTaintNode->Depth = crashNode->Depth + 1;
    TaintDFG.addEdge(crashNode, startTaintNode, EdgeType::Dereference);
    TaintDFG.updateLastTaintedNode(DestTi.Op, startTaintNode);
  }

  printTaintList(TL);
}

// Check if Ti represents a global variable and convert Ti into expected form.
// Expected form is $noreg plus offset, which is the global variable symbol
// address or the Global Offset Table entry.
bool crash_analyzer::TaintAnalysis::handleGlobalVar(TaintInfo &Ti) {

  if (!Dec || !Dec->getTarget())
    return false;

  if (!Ti.Op)
    return false;

  Optional<int64_t> ImmVal = llvm::None;
  // Get symbol address from Ti ({reg:$noreg; off:ADDR}).
  if (Ti.Op->isReg() && Ti.Op->getReg() == 0 && Ti.Offset)
    ImmVal = *Ti.Offset;

  bool Indirect = false;
  if (Ti.Op->isReg()) {
    auto CATI = getCATargetInfoInstance();
    const MachineFunction *MF = Ti.Op->getParent()->getMF();
    auto TRI = MF->getSubtarget().getRegisterInfo();
    std::string RegName = TRI->getRegAsmName(Ti.Op->getReg()).lower();
    // Get Global Offset Table entry address for Ti ({reg:$rip; off:GOT_ADDR}).
    if (CATI->isPCRegister(RegName) && Ti.Offset && Ti.IsTaintMemAddr()) {
      ImmVal = Ti.ConcreteMemoryAddress;
      Indirect = true;
    }
  }

  // Get symbol address from Ti ({imm:ADDR}).
  if (Ti.Op->isImm())
    ImmVal = Ti.Op->getImm();

  if (!ImmVal)
    return false;

  if (*ImmVal < 0)
    return false;

  uint64_t VarAddr = static_cast<uint64_t>(*ImmVal);
  // Read global symbol address from Global Offset Table.
  if (Indirect) {
    lldb::SBError err;
    VarAddr = Dec->getTarget()->GetProcess().ReadUnsignedFromMemory(
        static_cast<uint64_t>(VarAddr), 8, err);
  }

  auto SBTarget = Dec->getTarget();
  // Construct SBAddress for simbol from GOT.
  lldb::SBAddress SBAddr;
  SBAddr.SetLoadAddress((lldb::addr_t)VarAddr, *SBTarget);

  // Search symbols in each module for global var with the matching address.
  for (uint32_t Mods = 0; Mods < SBTarget->GetNumModules(); ++Mods) {
    auto SBModule = SBTarget->GetModuleAtIndex(Mods);
    if (SBModule.GetNumCompileUnits() != 1)
      continue;
    int NumSym = static_cast<int>(SBModule.GetNumSymbols());
    for (int i = 0; i < NumSym; i++) {
      auto SBSym = SBModule.GetSymbolAtIndex(i);
      auto SymAddr = SBSym.GetStartAddress().GetLoadAddress(*SBTarget);
      // Check if it is external symbol with the matching load address.
      if (SBSym.IsExternal() && SymAddr == SBAddr.GetLoadAddress(*SBTarget)) {
        // Convert Ti from {imm:ADDR} to {reg:$noreg; off:ADDR}
        // and ({reg:$rip; off:GOT_ADDR}) to {reg:$noreg; off:GOT_ADDR}
        if (Ti.Op->isImm() || Indirect) {
          Ti.Offset = static_cast<uint64_t>(*ImmVal);
          MachineOperand *MO2 = new MachineOperand(*Ti.Op);
          MO2->ChangeToRegister(0, false);
          Ti.Op = MO2;
          calculateMemAddr(Ti);
          LLVM_DEBUG(dbgs() << "Update Global Var Taint Info to " << Ti << "\n");
        }
        Ti.IsGlobal = true;
        return true;
      }
    }
  }

  return false;
}

void crash_analyzer::TaintAnalysis::addNewTaint(
    TaintInfo &Ti, SmallVectorImpl<TaintInfo> &TL, const MachineInstr &MI,
    TaintDataFlowGraph &TaintDFG, std::shared_ptr<Node> crashNode) {
  if (!Ti.Op)
    return;
  const auto &MF = MI.getParent()->getParent();

  if (addToTaintList(Ti, TL)) {
    Node *sNode = new Node(MF->getCrashOrder(), &MI, Ti, false);
    std::shared_ptr<Node> startTaintNode(sNode);
    // Set new node depth (crashNode has zero depth).
    startTaintNode->Depth = crashNode->Depth + 1;
    TaintDFG.addEdge(crashNode, startTaintNode, EdgeType::Dereference);
    TaintDFG.updateLastTaintedNode(Ti.Op, startTaintNode);
  }
}

void crash_analyzer::TaintAnalysis::startTaint(
    DestSourcePair &DS, SmallVectorImpl<TaintInfo> &TL, const MachineInstr &MI,
    TaintDataFlowGraph &TaintDFG, RegisterEquivalence &REAnalysis) {

  // Don't startTaint if target taint is explicitly specified.
  if (StartCrashOrder)
    return;

  // This condition is true only for frame #0 in back trace
  // Otherwise, it indicates that we did not find a taint
  // operand to begin with.
  if (TaintList.empty()) {
    // Currently we support building TaintInfo that represents only
    // memory locations expressed as one register plus one offset.
    // Scaled-index memory addresses cannot be expressed, but its
    // base registers can be Tainted.
    // Create TaintInfo only if it should be added to the TL.
    TaintInfo DestTi, DestBaseTi;
    TaintInfo DestIndexTi;

    // Create initial "crash" node.
    Node *cNode = new Node(0, nullptr, DestTi, true);
    std::shared_ptr<Node> crashNode(cNode);

    // Construct TaintInfo for destination operand, only if it is a memory
    // location. (ex. MOVrm rcx, 1, rax, 4, $noreg, 65)
    if (DS.DestOffset) {
      // Create base_reg+off Taint Info (ex. {reg:$rcx; off:4})
      // Only {reg + off} address can be calculated currently.
      if (!DS.DestIndexReg) {
        DestTi.Op = DS.Destination;
        DestTi.Offset = DS.DestOffset;
        calculateMemAddr(DestTi);
        handleGlobalVar(DestTi);
        addNewTaint(DestTi, TL, MI, TaintDFG, crashNode);
      }

      // Create base reg Taint Info (ex. {reg:$rcx;})
      DestBaseTi.Op = DS.Destination;
      DestBaseTi.Offset = llvm::None;
      DestBaseTi.IsConcreteMemory = false;
      DestBaseTi.ConcreteMemoryAddress = 0;
      addNewTaint(DestBaseTi, TL, MI, TaintDFG, crashNode);

      // Create index reg Taint Info (ex. {reg:$rax;})
      if (DS.DestIndexReg) {
        DestIndexTi.Op = DS.DestIndexReg;
        DestIndexTi.IsConcreteMemory = false;
        DestIndexTi.ConcreteMemoryAddress = 0;
        addNewTaint(DestIndexTi, TL, MI, TaintDFG, crashNode);
      }
    }

    TaintInfo SrcTi, SrcBaseTi;
    TaintInfo SrcIndexTi;
    // Process Taints from source operand (memory).
    // (ex. ebx = MOVrm rcx, 1, rax, 4)
    if (DS.SrcOffset) {
      // Create base_reg+off Taint Info (ex. {reg:$rcx; off:4})
      // Only {reg + off} address can be calculated currently.
      if (!DS.SrcIndexReg) {
        SrcTi.Op = DS.Source;
        SrcTi.Offset = DS.SrcOffset;
        calculateMemAddr(SrcTi);
        handleGlobalVar(SrcTi);
        addNewTaint(SrcTi, TL, MI, TaintDFG, crashNode);
      }

      // Create base reg Taint Info (ex. {reg:$rcx;})
      SrcBaseTi.Op = DS.Source;
      SrcBaseTi.Offset = llvm::None;
      SrcBaseTi.IsConcreteMemory = false;
      SrcBaseTi.ConcreteMemoryAddress = 0;
      addNewTaint(SrcBaseTi, TL, MI, TaintDFG, crashNode);

      // Create index reg Taint Info (ex. {reg:$rax;})
      if (DS.SrcIndexReg) {
        SrcIndexTi.Op = DS.SrcIndexReg;
        SrcIndexTi.IsConcreteMemory = false;
        SrcIndexTi.ConcreteMemoryAddress = 0;
        addNewTaint(SrcIndexTi, TL, MI, TaintDFG, crashNode);
      }
    }

    TaintInfo Src2Ti, Src2BaseTi;
    // Process Taints from 2nd source operand (memory).
    // (ex. CMP32rm $ebx, $rcx, 1, $rax, 4, $noreg)
    if (DS.Src2Offset) {
      // Create base_reg+off Taint Info (ex. {reg:$rcx; off:4})
      // Only {reg + off} address can be calculated currently.
      if (!DS.SrcIndexReg) {
        Src2Ti.Op = DS.Source2;
        Src2Ti.Offset = DS.Src2Offset;
        calculateMemAddr(Src2Ti);
        handleGlobalVar(Src2Ti);
        addNewTaint(Src2Ti, TL, MI, TaintDFG, crashNode);
      }

      // Create base reg Taint Info (ex. {reg:$rcx;})
      Src2BaseTi.Op = DS.Source2;
      Src2BaseTi.Offset = llvm::None;
      Src2BaseTi.IsConcreteMemory = false;
      Src2BaseTi.ConcreteMemoryAddress = 0;
      addNewTaint(Src2BaseTi, TL, MI, TaintDFG, crashNode);

      // Create index reg Taint Info (ex. {reg:$rax;})
      if (DS.SrcIndexReg) {
        SrcIndexTi.Op = DS.SrcIndexReg;
        SrcIndexTi.IsConcreteMemory = false;
        SrcIndexTi.ConcreteMemoryAddress = 0;
        addNewTaint(SrcIndexTi, TL, MI, TaintDFG, crashNode);
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
bool llvm::crash_analyzer::TaintAnalysis::propagateTaint(
    DestSourcePair &DS, SmallVectorImpl<TaintInfo> &TL, const MachineInstr &MI,
    TaintDataFlowGraph &TaintDFG, RegisterEquivalence &REAnalysis,
    const MachineInstr *CallMI) {
  // If empty taint list, we do nothing and we continue to
  // to propagate the taint along the other paths
  if (TL.empty() && !StartCrashOrder) {
    LLVM_DEBUG(dbgs() << "\n No taint to propagate\n");
    return true;
  }

  TaintInfo SrcTi, Src2Ti, DestTi;
  SrcTi.Op = DS.Source;
  SrcTi.Offset = DS.SrcOffset;
  if (SrcTi.Offset)
    calculateMemAddr(SrcTi);

  bool SrcGlobalVar = handleGlobalVar(SrcTi) && DS.Source->isImm();

  Src2Ti.Op = DS.Source2;
  Src2Ti.Offset = DS.Src2Offset;
  if (Src2Ti.Offset)
    calculateMemAddr(Src2Ti);

  DestTi.Op = DS.Destination;
  DestTi.Offset = DS.DestOffset;
  if (DestTi.Offset)
    calculateMemAddr(DestTi);
  handleGlobalVar(DestTi);

  if (!DestTi.Op)
    return true;

  // Check if Dest is already tainted.
  auto Taint = isTainted(DestTi, TL, &REAnalysis, &MI);

  const auto &MF = MI.getParent()->getParent();
  auto TII = MF->getSubtarget().getInstrInfo();
  // Check if DestTi is explicitly set as a starting point.
  if (DestTi.Op && DestTi.isTargetStartTaint(MF->getCrashOrder())) {
    insertTaint(DS, TL, MI, TaintDFG, REAnalysis);
    Taint = isTainted(DestTi, TL, &REAnalysis, &MI);
  }

  // If Destination is not tainted, nothing to do, just move on.
  if (Taint.Op == nullptr)
    return true;

  bool BaseTaintFlag = false;
  // Heuristic to allow taint propagation in certain cases
  // eg., when base + offset is a field of a struct
  // Check if base = base + offset condition
  // If base Op is tainted, retain the base Op in the taint list
  // Also add the base + offset to the taint list
  // FIXME : Adding base + offset is being conservative, doesn't
  // seem necessary for the cases at hand
  if (DestTi.Op->isReg() && SrcTi.Op->isReg()) {
    if (DestTi.Op->getReg() == SrcTi.Op->getReg())
      if (!DestTi.Offset && SrcTi.Offset)
        BaseTaintFlag = true;
  }

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
    // Set artificial Zero TaintInfo to ensure termination.
    TaintInfo ZeroTi;
    ZeroTi.Op = new MachineOperand(MachineOperand::CreateImm(0));
    SrcTi = ZeroTi;
    ConstantFound = true;
  }

  // Immediate operand, which is a symbol address for the global variable,
  // should not be treated as a constant.
  if (SrcGlobalVar)
    ConstantFound = false;

  // Propagate dereference level (from crash) from the Taint to the SrcTi.
  SrcTi.DerefLevel = Taint.DerefLevel;
  SrcTi.propagateDerefLevel(MI);

  // FIXME: Since now we have corefile content we can check if this constant
  // is the same from the crash point, and by doing that we avoid FALSE
  // positives -- CHECK THAT.
  if (ConstantFound) {
    Node *constantNode = new Node(MF->getCrashOrder(), &MI, SrcTi, false, true);
    // FIXME: Improve this code.
    // This will be used to indentify call instruction when analyzing fns out of
    // bt.
    if (CallMI)
      constantNode->CallMI = CallMI;
    std::shared_ptr<Node> constNode(constantNode);
    auto &LastTaintedNodeForTheOp = TaintDFG.lastTaintedNode[Taint.Op];
    TaintDFG.addEdge(LastTaintedNodeForTheOp, constNode, EdgeType::Dereference);
    // FIXME: The LastTaintedNode won't be used any more, no need for this line?
    TaintDFG.updateLastTaintedNode(SrcTi.Op, constNode);
    // Set new node depth.
    constNode->Depth = LastTaintedNodeForTheOp->Depth + 1;

    // We have reached a terminating condition where
    // dest is tainted and src is a constant operand.
    removeFromTaintList(Taint, TL);
  }

  if (addToTaintList(SrcTi, TL)) {
    Node *newNode = new Node(MF->getCrashOrder(), &MI, SrcTi, false);
    if (CallMI)
      newNode->CallMI = CallMI;
    std::shared_ptr<Node> newTaintNode(newNode);
    // TODO: Check if this should be a deref edge:
    //       if we propagate taint from a mem addr (e.g. rbx + 10)
    //       to its base reg (e.g. rbx).
    assert(TaintDFG.lastTaintedNode.count(Taint.Op) &&
           "Taint Op must be reached already");
    auto &LastTaintedNodeForTheOp = TaintDFG.lastTaintedNode[Taint.Op];

    if (LastTaintedNodeForTheOp->TaintOp.Op->isReg() &&
        LastTaintedNodeForTheOp->TaintOp.Offset &&
        newTaintNode->TaintOp.Op->isReg() &&
        (LastTaintedNodeForTheOp->TaintOp.Op->getReg() ==
         newTaintNode->TaintOp.Op->getReg()))
      TaintDFG.addEdge(LastTaintedNodeForTheOp, newTaintNode,
                       EdgeType::Dereference);
    else
      TaintDFG.addEdge(LastTaintedNodeForTheOp, newTaintNode);
    TaintDFG.updateLastTaintedNode(SrcTi.Op, newTaintNode);
    // Set new node depth.
    newTaintNode->Depth = LastTaintedNodeForTheOp->Depth + 1;

    if (!BaseTaintFlag)
      removeFromTaintList(Taint, TL);
    else
      // FIXME: Update DerefLevel of Taint's equivalent in TL or remove it
      // and insert Taint again?
      updateTaintDerefLevel(Taint, TL, MI);
  }

  printTaintList(TL);
  return true;
}


// Simplified version of propagateTaint, but in the oposite (forward) direction.
// Idea is to track tainted parameters of out-of-the-backtrace calls, from the
// function entry point, to the spot where the parameter value is set.
// (From that spot, we would go backwards to find the origin of the value.)
bool llvm::crash_analyzer::TaintAnalysis::propagateTaintFwd(
    DestSourcePair &DS, SmallVectorImpl<TaintInfo> &TL, const MachineInstr &MI,
    TaintDataFlowGraph &TaintDFG, RegisterEquivalence &REAnalysis,
    const MachineInstr *CallMI) {

  TaintInfo SrcTi, DestTi;
  SrcTi.Op = DS.Source;
  SrcTi.Offset = DS.SrcOffset;
  DestTi.Op = DS.Destination;
  DestTi.Offset = DS.DestOffset;

  if (!SrcTi.Op)
    return true;

  const auto &MF = MI.getParent()->getParent();
  auto TII = MF->getSubtarget().getInstrInfo();

  auto DestTaint = isTainted(DestTi, TL, &REAnalysis, &MI);
  // FIXME: Define better terminating criteria for forward analysis?
  if (SrcTi.Op->isImm()) {
    if (DestTaint.Op == nullptr)
      return true;
    // Propagate dereference level (from crash) from the Taint (DestTi) to the
    // SrcTi. This propagation is in the backwards direction.
    SrcTi.DerefLevel = DestTaint.DerefLevel;
    SrcTi.propagateDerefLevel(MI);

    Node *constantNode = new Node(MF->getCrashOrder(), &MI, SrcTi, false, true);
    // FIXME: Improve this code.
    // This will be used to indentify call instruction when analyzing fns out of
    // bt.
    if (CallMI)
      constantNode->CallMI = CallMI;
    std::shared_ptr<Node> constNode(constantNode);
    auto &LastTaintedNodeForTheOp = TaintDFG.lastTaintedNode[DestTaint.Op];
    TaintDFG.addEdge(LastTaintedNodeForTheOp, constNode, EdgeType::Dereference);
    // FIXME: The LastTaintedNode won't be used any more, no need for this line?
    TaintDFG.updateLastTaintedNode(SrcTi.Op, constNode);
    constNode->Depth = LastTaintedNodeForTheOp->Depth + 1;
    // We have reached a terminating condition where
    // dest is tainted and src is a constant operand.
    removeFromTaintList(DestTaint, TL);
    return false;
  }

  // Check if SrcTi is already tainted.
  auto Taint = isTainted(SrcTi, TL, &REAnalysis, &MI);

  // If SrcTi is not tainted, check if the base reg is tainted.
  if (Taint.Op == nullptr && SrcTi.Offset) {
    TaintInfo SrcBase;
    SrcBase.Op = SrcTi.Op;
    Taint = isTainted(SrcBase, TL, &REAnalysis, &MI);
  }

  // If Source is not tainted, nothing to do, just move on.
  if (Taint.Op == nullptr)
    return true;

  // Propagate dereference level (from crash) from the Taint to the DestTi.
  // This propagation is in the forwards direction.
  DestTi.DerefLevel = Taint.DerefLevel;
  // Inverse DestTi.propagateDerefLevel(MI);
  if (TII->isStore(MI))
    DestTi.DerefLevel -= 1;
  else if (TII->isLoad(MI))
    DestTi.DerefLevel += 1;

  // Add new TaintDFG node for the DestTi.
  if (addToTaintList(DestTi, TL)) {
    Node *newNode = new Node(MF->getCrashOrder(), &MI, DestTi, false);
    if (CallMI)
      newNode->CallMI = CallMI;
    std::shared_ptr<Node> newTaintNode(newNode);
    assert(TaintDFG.lastTaintedNode.count(Taint.Op) &&
           "Taint Op must be reached already");
    auto &LastTaintedNodeForTheOp = TaintDFG.lastTaintedNode[Taint.Op];
    // Set new node depth.
    newTaintNode->Depth = LastTaintedNodeForTheOp->Depth + 1;

    if (LastTaintedNodeForTheOp->TaintOp.Op->isReg() &&
        LastTaintedNodeForTheOp->TaintOp.Offset &&
        newTaintNode->TaintOp.Op->isReg() &&
        (LastTaintedNodeForTheOp->TaintOp.Op->getReg() ==
         newTaintNode->TaintOp.Op->getReg()))
      TaintDFG.addEdge(LastTaintedNodeForTheOp, newTaintNode,
                       EdgeType::Dereference);
    else
      TaintDFG.addEdge(LastTaintedNodeForTheOp, newTaintNode);
    TaintDFG.updateLastTaintedNode(DestTi.Op, newTaintNode);

    // TODO: Handle cases where we don't remove the Taint, like struct field
    // access.
    removeFromTaintList(Taint, TL);
  }
  printTaintList(TL);
  return true;
}

// Simplified version of runOnBlameMF, but in the oposite (forward) direction.
// Idea is to propagate the Taint from parameter (function entry point) to the
// program point, where the parameter's value is set.
bool crash_analyzer::TaintAnalysis::forwardMFAnalysis(
    BlameModule &BM, const MachineFunction &MF, TaintDataFlowGraph &TaintDFG,
    unsigned levelOfCalledFn, SmallVector<TaintInfo, 8> *TL_Of_Caller,
    const MachineInstr *CallMI) {
  LLVM_DEBUG(llvm::dbgs() << "### MF - forward analysis: " << MF.getName()
                          << "\n";);
  printTaintList(*TL_Of_Caller);

  // Run the forward analysis to compute register equivalance.
  RegisterEquivalence REAnalysis;
  REAnalysis.init(const_cast<MachineFunction &>(MF));
  REAnalysis.run(const_cast<MachineFunction &>(MF));

  // Per function : Map MBB with its Taint List
  DenseMap<const MachineBasicBlock *, SmallVector<TaintInfo, 8>> MBB_TL_Map;

  // Initialize all the MBB with emtpty taint list
  for (const MachineBasicBlock &MBB : MF) {
    SmallVector<TaintInfo, 8> _tmp;
    MBB_TL_Map[&MBB] = _tmp;
  }

  auto TII = MF.getSubtarget().getInstrInfo();

  // Perform forward analysis on the MF.
  for (auto MBBIt = ipo_begin(&MF.front()), MBBIt_E = ipo_end(&MF.front());
       MBBIt != MBBIt_E; ++MBBIt) {
    auto MBB = *MBBIt;
    SmallVector<TaintInfo, 8> &TL_Mbb = MBB_TL_Map.find(MBB)->second;

    // Initialize Taint list for a MBB
    for (const MachineBasicBlock *Pred : MBB->predecessors()) {
      mergeTaintList(TL_Mbb, MBB_TL_Map.find(Pred)->second);
    }
    if (MBB->pred_empty())
      mergeTaintList(TL_Mbb, *TL_Of_Caller);
    TL_Of_Caller->clear();

    // If Taint List for an MBB is empty, then no need to analyze this MBB
    printTaintList(TL_Mbb);
    if (TL_Mbb.empty())
      continue;

    for (auto MIIt = MBB->begin(); MIIt != MBB->end(); ++MIIt) {
      auto &MI = *MIIt;

      // Stop analyzing this MBB.
      if (MI.isBranch() || MI.isReturn())
        break;

      // Skip push.
      if (TII->isPush(MI))
        continue;

      // Forward analysis doesn't step into nested calls, that is done in
      // the backward analysis (runOnBlameMF).
      if (MI.isCall())
        continue;

      auto DestSrc = TII->getDestAndSrc(MI);
      if (!DestSrc) {
        MI.dump();
        LLVM_DEBUG(llvm::dbgs()
                       << "haven't found dest && source for the MI\n";);
        bool toContinue = continueAnalysis(MI, TL_Mbb, REAnalysis);
        if (!toContinue) {
          WithColor::error(errs())
              << "MIR not handled; Unable to propagate taint analysis\n";
          abortAnalysis = true;
          return false;
        }
        continue;
      }

      printDestSrcInfo(*DestSrc, MI);
      propagateTaintFwd(*DestSrc, TL_Mbb, MI, TaintDFG, REAnalysis, CallMI);
    }
    // At the end, if we didn't find the blame in this function, the
    // TL_Of_Caller should contain locations to continue backward analysis of
    // this function (including nested calls).
    mergeTaintList(*TL_Of_Caller, TL_Mbb);
  }

  return true;
}

void crash_analyzer::TaintAnalysis::setCRE(ConcreteReverseExec *cre) {
  CRE = cre;
}
ConcreteReverseExec *crash_analyzer::TaintAnalysis::getCRE() const {
  return CRE;
}

void crash_analyzer::TaintAnalysis::setREAnalysis(RegisterEquivalence *rea) {
  REA = rea;
}
RegisterEquivalence *crash_analyzer::TaintAnalysis::getREAnalysis() {
  return REA;
}

// Transform stack memory locations in the TaintList, to use Base Pointer as a
// base register (callee side), instead of the Stack Pointer (caller side).
void crash_analyzer::TaintAnalysis::transformSPtoBPTaints(
    const MachineFunction &MF, TaintDataFlowGraph &TaintDFG,
    SmallVectorImpl<TaintInfo> &TL) {
  auto TRI = MF.getSubtarget().getRegisterInfo();
  auto CATI = getCATargetInfoInstance();

  for (auto itr = TL.begin(); itr != TL.end(); ++itr) {
    if (!itr->Op || !itr->Op->isReg())
      continue;
    if (itr->IsConcreteMemory)
      continue;
    Register Reg = itr->Op->getReg();
    std::string RegName = TRI->getRegAsmName(Reg).lower();
    if (!CATI->isSPRegister(RegName))
      continue;
    // Transform $rsp + off -> $rbp + ADJUSTMENT + off
    // For X86, ADJUSTMENT is 16 (sizeof(rip) + sizeof(rbp)).
    if (!CATI->getBP())
      break;
    auto BpReg = CATI->getRegister(*CATI->getBP(), itr->Op->getParent());
    if (!BpReg)
      break;

    assert(TaintDFG.lastTaintedNode.count(itr->Op) &&
           "Taint Op must be reached already");
    auto &LastTaintedNodeForTheOp = TaintDFG.lastTaintedNode[itr->Op];

    LLVM_DEBUG(llvm::dbgs() << "Caller-side: " << *itr);
    MachineOperand MOp = MachineOperand::CreateReg(MCRegister(*BpReg), false);
    MOp.setParent(const_cast<MachineInstr *>(itr->Op->getParent()));
    itr->Op = new MachineOperand(MOp);
    *itr->Offset = *itr->Offset + CATI->getSPAdjust();
    LLVM_DEBUG(llvm::dbgs() << " -> Callee-side:" << *itr << "\n");
    // Update LastTaintedNode with the transformed TaintInfo.
    TaintDFG.updateLastTaintedNode(itr->Op, LastTaintedNodeForTheOp);
  }
}

// Transform stack memory locations in the TaintList, to use Stack Pointer as a
// base register (caller side), instead of the Base Pointer (callee side).
void crash_analyzer::TaintAnalysis::transformBPtoSPTaints(
    const MachineFunction &MF, TaintDataFlowGraph &TaintDFG,
    SmallVectorImpl<TaintInfo> &TL) {
  auto TRI = MF.getSubtarget().getRegisterInfo();
  auto CATI = getCATargetInfoInstance();

  for (auto itr = TL.begin(); itr != TL.end(); ++itr) {
    if (!itr->Op || !itr->Op->isReg())
      continue;
    if (itr->IsConcreteMemory)
      continue;
    Register Reg = itr->Op->getReg();
    std::string RegName = TRI->getRegAsmName(Reg).lower();
    if (!CATI->isBPRegister(RegName))
      continue;
    // Transform $rbp + ADJUSTMENT + off ->  $rsp + off
    // For X86, ADJUSTMENT is 16 (sizeof(rip) + sizeof(rbp)).
    if (!CATI->getSP())
      break;
    auto SpReg = CATI->getRegister(*CATI->getSP(), itr->Op->getParent());
    if (!SpReg)
      break;

    assert(TaintDFG.lastTaintedNode.count(itr->Op) &&
           "Taint Op must be reached already");
    auto &LastTaintedNodeForTheOp = TaintDFG.lastTaintedNode[itr->Op];

    LLVM_DEBUG(llvm::dbgs() << "Callee-side: " << *itr);
    MachineOperand MOp = MachineOperand::CreateReg(MCRegister(*SpReg), false);
    MOp.setParent(const_cast<MachineInstr *>(itr->Op->getParent()));
    itr->Op = new MachineOperand(MOp);
    *itr->Offset = *itr->Offset - CATI->getSPAdjust();
    LLVM_DEBUG(llvm::dbgs() << " -> Caller-side:" << *itr << "\n");
    // Update LastTaintedNode with the transformed TaintInfo.
    TaintDFG.updateLastTaintedNode(itr->Op, LastTaintedNodeForTheOp);
  }
}

// Return true if taint is terminated.
// Return false otherwise.
bool crash_analyzer::TaintAnalysis::runOnBlameMF(
    BlameModule &BM, const MachineFunction &MF, TaintDataFlowGraph &TaintDFG,
    bool CalleeNotInBT, unsigned levelOfCalledFn,
    SmallVector<TaintInfo, 8> *TL_Of_Caller, const MachineInstr *CallMI) {
  LLVM_DEBUG(llvm::dbgs() << "### MF - backward analysis: " << MF.getName()
                          << "\n";);

  // Run the forward analysis to compute register equivalance.
  RegisterEquivalence REAnalysis;
  REAnalysis.init(const_cast<MachineFunction &>(MF));
  REAnalysis.run(const_cast<MachineFunction &>(MF));
  setREAnalysis(&REAnalysis);

  // Init the concrete reverse execution.
  ConcreteReverseExec ReverseExecutionRecord(&MF);
  setCRE(&ReverseExecutionRecord);
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
      // Consider crash-start instruction when analyzing functions from the
      // backtrace.
      if (!CalleeNotInBT && MI.getFlag(MachineInstr::CrashStart)) {
        CrashSequenceStarted = true;

        // For frames > 0, skip to the first instruction after the call
        // instruction, traversing backwards.
        // Sometimes analysis starts at some frame != 1, due to some inlined fns
        // preceding that fn.
        if ((MF.getCrashOrder() > 1 &&
             MF.getCrashOrder() != analysisStartedAt) ||
            CalleeNotInBT) {
          if (!CalleeNotInBT) {
            // Skip processing crash instruction
            ++MIIt;
            if (MIIt == MBB->rend())
              return Result;
          }
          // Update PC for CALL instruction.
          ReverseExecutionRecord.updatePC(*MIIt);
          // Skip processing the call instruction
          ++MIIt;
          if (MIIt == MBB->rend())
            return Result;
        }
        auto &MI2 = *MIIt;
        // Update PC register value for MI2.
        ReverseExecutionRecord.updatePC(MI2);
        // Process the call instruction that is not in the backtrace
        // Analyze the call only if return value is tainted.
        // For now we are interested in depth of 10 functions (call->call->..).
        // TODO: Handling of function parameters that are tainted
        // within the function.
        if (MI2.isCall() && levelOfCalledFn < FrameLevelDepthToGo) {
          mergeTaintList(TL_Mbb, TaintList);
          const MachineOperand &CalleeOp = MI2.getOperand(0);
          // TODO: handle indirect calls.
          if (!CalleeOp.isGlobal())
            continue;
          auto TargetName = CalleeOp.getGlobal()->getName();
          if (!shouldAnalyzeCall(TL_Mbb)) {
            LLVM_DEBUG(llvm::dbgs()
                       << "Not Analyzing function " << TargetName << "\n");
            continue;
          }
          if (CalleeOp.isGlobal()) {
            MachineFunction *CalledMF = getCalledMF(BM, TargetName.str());
            if (CalledMF) {
              LLVM_DEBUG(llvm::dbgs() << "#### Processing callee " << TargetName
                                      << "\n";);
              CalledMF->setCrashOrder(MF.getCrashOrder());
              runOnBlameMF(BM, *CalledMF, TaintDFG, true, ++levelOfCalledFn,
                           &TL_Mbb, &MI2);
              CalledMF->setCrashOrder(0);
              continue;
            } else {
              if (!getIsCrashAnalyzerTATool()) {
                MachineFunction *MFOnDemand =
                    Dec->decompileOnDemand(TargetName);
                if (!MFOnDemand) {
                  LLVM_DEBUG(llvm::dbgs() << "#### Callee not found: "
                                          << TargetName << "\n";);
                  // TODO: Check if the Analysis can still be continued
                  return Result;
                } else {
                  MFOnDemand->setCrashOrder(MF.getCrashOrder());
                  runOnBlameMF(BM, *MFOnDemand, TaintDFG, true,
                               ++levelOfCalledFn, &TL_Mbb, &MI);
                  MFOnDemand->setCrashOrder(0);
                }
              } else {
                LLVM_DEBUG(llvm::dbgs() << "#### Callee not found: "
                                        << TargetName << "\n";);
                // TODO: Check if the Analysis can still be continued
                return Result;
              }
            }
          }
        }
        auto DestSrc = TII->getDestAndSrc(MI2);
        if (!DestSrc) {
          LLVM_DEBUG(llvm::dbgs()
                         << "Crash instruction doesn't have blame operands\n";
                     MI2.dump(););
          // If we found no taint operand to begin with in the first frame
          // then terminate the analysis.
          // The first frame could be frame #0 with CrashOrder = 1 (or)
          // found after several inlined frames in the beginning of the
          // backtrace.
          if ((MF.getCrashOrder() == 1) ||
              (MF.getCrashOrder() == analysisStartedAt)) {
            llvm::errs() << "\nNo Taint operand to begin analysis.";
            return true;
          }
          mergeTaintList(TL_Mbb, TaintList);
          continue;
        }
        printDestSrcInfo(*DestSrc, MI2);
        startTaint(*DestSrc, TL_Mbb, MI2, TaintDFG, REAnalysis);
        continue;
      }

      // Skip until crash-start instruction.
      if (!CrashSequenceStarted) {
        // If we analyze call out of the backtrace, even if the function
        // is already decompiled (is in the backtrace as well), do not
        // skip.
        if (!CalleeNotInBT)
          continue;
        // For functions out of the BT, start TA from the last instruction.
        CrashSequenceStarted = true;
        // If this was a call to a function that isn't in the bt,
        // the analysis will start from the last intr (return), so
        // we need just to consider the taint operands from the MBB
        // where it got called.
        mergeTaintList(TL_Mbb, *TL_Of_Caller);
        TL_Of_Caller->clear();
      }

      // Update the register values (including PC reg), so we have right
      // register values state.
      ReverseExecutionRecord.updatePC(MI);
      ReverseExecutionRecord.execute(MI);

      // Process call instruction that is not in backtrace
      // Analyze the call only if return value is tainted.
      // TBD: We ignore tainted parameters since we do not have a good
      // way to identify machine operands that are function parameters.
      if (MI.isCall() && levelOfCalledFn < FrameLevelDepthToGo) {
        //  mergeTaintList(TL_Mbb, TaintList); Is this needed (as above) ?
        const MachineOperand &CalleeOp = MI.getOperand(0);
        TL_Of_Call.clear();
        // TODO: handle indirect calls.
        if (!CalleeOp.isGlobal())
          continue;

        bool runFwAnalysis =
            areParamsTainted(&MI, TL_Mbb, &TL_Of_Call, TaintDFG, *REA) ||
            isStackSlotTainted(&MI, TL_Mbb, &TL_Of_Call, TaintDFG, REA);
        bool runBwAnalysis = shouldAnalyzeCall(TL_Mbb);

        auto TargetName = CalleeOp.getGlobal()->getName();
        if (!runBwAnalysis && !runFwAnalysis) {
          LLVM_DEBUG(llvm::dbgs()
                     << "Not Analyzing function " << TargetName << "\n");
          continue;
        }
        MachineFunction *CalledMF = getCalledMF(BM, TargetName.str());
        if (CalledMF) {
          CalledMF->setCrashOrder(MF.getCrashOrder());
          if (runBwAnalysis)
            runOnBlameMF(BM, *CalledMF, TaintDFG, true, levelOfCalledFn + 1,
                         &TL_Mbb, &MI);
          CalledMF->setCrashOrder(MF.getCrashOrder() + 1);
          // If parameter is tainted, run analysis from the function entry point
          // (forward), to the point where the parameter value is set.
          if (runFwAnalysis) {
            // Before call analysis, transform stack location TaintInfo to
            // match the callee frame pointer.
            transformSPtoBPTaints(MF, TaintDFG, TL_Of_Call);
            printTaintList(TL_Of_Call);
            forwardMFAnalysis(BM, *CalledMF, TaintDFG, levelOfCalledFn + 1,
                              &TL_Of_Call, &MI);
            // If there is a Taint left after the forward analysis, run backward
            // analysis for the same TaintList. (ex. one parameter sets the
            // value of another)
            if (!TL_Of_Call.empty()) {
              printTaintList(TL_Of_Call);
              runOnBlameMF(BM, *CalledMF, TaintDFG, true, levelOfCalledFn + 1,
                           &TL_Of_Call, &MI);
            }
            // After call analysis, transform stack location TaintInfo to
            // match the caller stack pointer.
            transformBPtoSPTaints(MF, TaintDFG, TL_Of_Call);
            mergeTaintList(TL_Mbb, TL_Of_Call);
            TL_Of_Call.clear();
            LLVM_DEBUG(llvm::dbgs() << "### Return to backward analysis: "
                                    << MF.getName() << "\n";);
          }
          CalledMF->setCrashOrder(0);
          continue;
        } else {
          if (!getIsCrashAnalyzerTATool()) {
            MachineFunction *MFOnDemand = Dec->decompileOnDemand(TargetName);
            if (!MFOnDemand) {
              LLVM_DEBUG(llvm::dbgs() << "#### Callee not found: " << TargetName
                                      << "\n";);
              continue;
            } else {
              // Handle it.
              MFOnDemand->setCrashOrder(MF.getCrashOrder());
              if (runBwAnalysis)
                runOnBlameMF(BM, *MFOnDemand, TaintDFG, true,
                             levelOfCalledFn + 1, &TL_Mbb, &MI);

              MFOnDemand->setCrashOrder(MF.getCrashOrder() + 1);
              // If parameter is tainted, run analysis from the function entry
              // point (forward), to the point where the parameter value is set.
              if (runFwAnalysis) {
                // Before call analysis, transform stack location TaintInfo to
                // match the callee frame pointer.
                transformSPtoBPTaints(MF, TaintDFG, TL_Of_Call);
                printTaintList(TL_Of_Call);
                forwardMFAnalysis(BM, *MFOnDemand, TaintDFG,
                                  levelOfCalledFn + 1, &TL_Of_Call, &MI);
                // If there is a Taint left after the forward analysis, run
                // backward analysis for the same TaintList. (ex. one parameter
                // sets the value of another)
                if (!TL_Of_Call.empty()) {
                  printTaintList(TL_Of_Call);
                  runOnBlameMF(BM, *MFOnDemand, TaintDFG, true,
                               levelOfCalledFn + 1, &TL_Of_Call, &MI);
                }
                // After call analysis, transform stack location TaintInfo to
                // match the caller stack pointer.
                transformBPtoSPTaints(MF, TaintDFG, TL_Of_Call);
                mergeTaintList(TL_Mbb, TL_Of_Call);
                TL_Of_Call.clear();
                LLVM_DEBUG(llvm::dbgs() << "### Return to backward analysis: "
                                        << MF.getName() << "\n";);
              }
              MFOnDemand->setCrashOrder(0);
            }
            continue;
          } else {
            LLVM_DEBUG(llvm::dbgs()
                           << "#### Callee not found: " << TargetName << "\n";);
            continue;
          }
        }
      }

      if (MI.isBranch() || MI.isReturn())
        continue;

      // We reached the end of the frame.
      if (TII->isPush(MI))
        break;

      auto DestSrc = TII->getDestAndSrc(MI);
      if (!DestSrc) {
        MI.dump();
        LLVM_DEBUG(llvm::dbgs()
                       << "haven't found dest && source for the MI\n";);
        bool toContinue = continueAnalysis(MI, TL_Mbb, REAnalysis);
        if (!toContinue) {
          WithColor::error(errs())
              << "MIR not handled; Unable to propagate taint analysis\n";
          abortAnalysis = true;
          return false;
        }
        continue;
      }

      printDestSrcInfo(*DestSrc, MI);

      // Backward Taint Analysis.
      bool TaintResult =
          propagateTaint(*DestSrc, TL_Mbb, MI, TaintDFG, REAnalysis, CallMI);
      if (!TaintResult)
        Result = true;
    }
    // Update TL_Of_Caller to be available in the parent call.
    if (CalleeNotInBT)
      mergeTaintList(*TL_Of_Caller, TL_Mbb);
  }
  resetTaintList(*CurTL);
  setREAnalysis(nullptr);
  setCRE(nullptr);

  return Result;
}

// Dummy MFs of our inlined frames have dummy NOOP instruction only.
static bool isInline(MachineFunction *MF) {
  if (!MF)
    return false;

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
bool crash_analyzer::TaintAnalysis::runOnBlameModule(BlameModule &BM) {
  bool AnalysisStarted = false;
  bool Result = false;

  llvm::outs() << "\nAnalyzing...\n";

  TaintDataFlowGraph TaintDFG;

  // Run the analysis on each blame function.
  for (auto &BF : BM) {
    // TODO: Handling of functions like _start, __libc_start_main, etc

    if (!AnalysisStarted) {
      if (!BF.MF) {
        llvm::outs() << "Analysis stopped since a function on top "
                     << "of the backtrace doesn't have symbols.\n";
        return Result;
      }
    }
    // Skip frames if explicit start frame is not reached.
    if (BF.MF->getCrashOrder() < StartCrashOrder)
      continue;

    if (!BF.MF->getCrashOrder()) {
      LLVM_DEBUG(llvm::dbgs()
                     << "### Skip a call target: " << BF.Name << "\n";);
      continue;
    }

    if (isInline(BF.MF)) {
      LLVM_DEBUG(llvm::dbgs() << "### Skip inline fn: " << BF.Name << "\n";);
      ++analysisStartedAt;
      continue;
    }

    AnalysisStarted = true;
    // If we have found a MF that we hadn't decompiled (to LLVM MIR), stop
    // the analysis there, since it is a situation where a frame is missing.
    if (!BF.MF) {
      LLVM_DEBUG(llvm::dbgs() << "### Empty MF: " << BF.Name << "\n";);
      auto FnName = BF.Name;
      if (FnName == "")
        FnName = "???";
      WithColor::warning() << "No symbols found for function " << FnName
                           << " from backtrace"
                           << ", so analysis is stopped there.\n";
      if (!MirDotFileName.empty()) {
        TaintDFG.printAsDOT(MirDotFileName.str());
      }
      TaintDFG.dump();
      // Dump user friendly DFG.
      if (!TaintDotFileName.empty()) {
        TaintDFG.printAsDOT(TaintDotFileName.str(), true /*Verbose*/);
      }
      if (!TaintDFG.getBlameNodesSize()) {
        llvm::outs() << "\nNo blame function found.\n";
        return false;
      }
      auto crashNode = TaintDFG.getCrashNode();
      TaintDFG.findBlameFunction(crashNode);
      Result = TaintDFG.printBlameFunction(PrintPotentialCrashCauseLocation);
      return Result;
    }

    runOnBlameMF(BM, *(BF.MF), TaintDFG, false, 0);

    // After the MF analysis, if the TaintList is empty, stop the analysis.
    if (TaintList.empty()) {
      LLVM_DEBUG(dbgs() << "\nTaint Analysis done.\n");
      if (!MirDotFileName.empty()) {
        TaintDFG.printAsDOT(MirDotFileName.str());
      }
      TaintDFG.dump();

      // Dump user friendly DFG.
      if (!TaintDotFileName.empty()) {
        TaintDFG.printAsDOT(TaintDotFileName.str(), true /*Verbose*/);
      }

      if (!TaintDFG.getBlameNodesSize()) {
        llvm::outs() << "\nNo blame function found.\n";
        return false;
      }

      auto crashNode = TaintDFG.getCrashNode();
      TaintDFG.findBlameFunction(crashNode);
      Result = TaintDFG.printBlameFunction(PrintPotentialCrashCauseLocation);
      return Result;
    }
  }

  if (!MirDotFileName.empty()) {
    TaintDFG.printAsDOT(MirDotFileName.str());
  }

  TaintDFG.dump();

  // Dump user friendly DFG.
  if (!TaintDotFileName.empty()) {
    TaintDFG.printAsDOT(TaintDotFileName.str(), true /*Verbose*/);
  }

  if (!TaintDFG.getBlameNodesSize()) {
    llvm::outs() << "\nNo blame function found.\n";
    return false;
  }

  // Do not print blame function if taint propagation was
  // prematurely terminated.
  if (!abortAnalysis) {
    auto crashNode = TaintDFG.getCrashNode();
    TaintDFG.findBlameFunction(crashNode);
    Result = TaintDFG.printBlameFunction(PrintPotentialCrashCauseLocation);
  }

  // Currently we report SUCCESS even if one Blame Function is found.
  // Ideally SUCCESS is only when TaintList.empty() is true.
  return Result;
}
