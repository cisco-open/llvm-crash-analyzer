//===- MachineLocTracking.cpp - Forward analysis - machine loc tracking ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/MachineLocTracking.h"

#include "llvm/CodeGen/PseudoSourceValue.h"
#include "llvm/IR/Module.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"

#include <queue>
#include <tuple>

#define DEBUG_TYPE "machinelocdataflow"

using namespace llvm;

SpillLoc
MachineLocTracking::extractSpillBaseRegAndOffset(const MachineInstr &MI) {
  assert(MI.hasOneMemOperand() &&
         "Spill instruction does not have exactly one memory operand?");
  auto MMOI = MI.memoperands_begin();
  const PseudoSourceValue *PVal = (*MMOI)->getPseudoValue();
  assert(PVal->kind() == PseudoSourceValue::FixedStack &&
         "Inconsistent memory operand in spill instruction");
  int FI = cast<FixedStackPseudoSourceValue>(PVal)->getFrameIndex();
  const MachineBasicBlock *MBB = MI.getParent();
  unsigned Reg;
  int Offset = TFI->getFrameIndexReference(*MBB->getParent(), FI, Reg);
  return {Reg, Offset};
}

void MachineLocTracking::transferRegisterDef(MachineInstr &MI) {
  // Meta Instructions do not affect the debug liveness of any register they
  // define.
  if (MI.isImplicitDef()) {
    // Except when there's an implicit def, and the location it's defining has
    // no value number. The whole point of an implicit def is to announce that
    // the register is live, without be specific about it's value. So define
    // a value if there isn't one already.
    ValueIDNum Num = MTracker->readReg(MI.getOperand(0).getReg());
    // Has a legitimate value -> ignore the implicit def.
    if (Num.getLoc() != 0)
      return;
    // Otherwise, def it here.
  } else if (MI.isMetaInstruction())
    return;

  MachineFunction *MF = MI.getMF();
  const TargetLowering *TLI = MF->getSubtarget().getTargetLowering();
  Register SP = TLI->getStackPointerRegisterToSaveRestore();

  // Find the regs killed by MI, and find regmasks of preserved regs.
  // Max out the number of statically allocated elements in `DeadRegs`, as this
  // prevents fallback to std::set::count() operations.
  SmallSet<uint32_t, 32> DeadRegs;
  SmallVector<const uint32_t *, 4> RegMasks;
  SmallVector<const MachineOperand *, 4> RegMaskPtrs;
  for (const MachineOperand &MO : MI.operands()) {
    // Determine whether the operand is a register def.
    if (MO.isReg() && MO.isDef() && MO.getReg() &&
        Register::isPhysicalRegister(MO.getReg()) &&
        !(MI.isCall() && MO.getReg() == SP)) {
      // Remove ranges of all aliased registers.
      for (MCRegAliasIterator RAI(MO.getReg(), TRI, true); RAI.isValid(); ++RAI)
        // FIXME: Can we break out of this loop early if no insertion occurs?
        DeadRegs.insert(*RAI);
    } else if (MO.isRegMask()) {
      RegMasks.push_back(MO.getRegMask());
      RegMaskPtrs.push_back(&MO);
    }
  }

  // Tell MLocTracker about all definitions, of regmasks and otherwise.
  for (uint32_t DeadReg : DeadRegs)
    MTracker->defReg(DeadReg, CurBB, CurInst);

  for (auto *MO : RegMaskPtrs)
    MTracker->writeRegMask(MO, CurBB, CurInst);
}

void MachineLocTracking::performCopy(Register SrcRegNum, Register DstRegNum) {
  ValueIDNum SrcValue = MTracker->readReg(SrcRegNum);

  MTracker->setReg(DstRegNum, SrcValue);

  // In all circumstances, re-def the super registers. It's definitely a new
  // value now. This doesn't uniquely identify the composition of subregs, for
  // example, two identical values in subregisters composed in different
  // places would not get equal value numbers.
  for (MCSuperRegIterator SRI(DstRegNum, TRI); SRI.isValid(); ++SRI)
    MTracker->defReg(*SRI, CurBB, CurInst);

  // Otherwise, actually copy subregisters from one location to another.
  // XXX: in addition, any subregisters of DstRegNum that don't line up with
  // the source register should be def'd.
  for (MCSubRegIndexIterator SRI(SrcRegNum, TRI); SRI.isValid(); ++SRI) {
    unsigned SrcSubReg = SRI.getSubReg();
    unsigned SubRegIdx = SRI.getSubRegIndex();
    unsigned DstSubReg = TRI->getSubReg(DstRegNum, SubRegIdx);
    if (!DstSubReg)
      continue;

    // Do copy. There are two matching subregisters, the source value should
    // have been def'd when the super-reg was, the latter might not be tracked
    // yet.
    // This will force SrcSubReg to be tracked, if it isn't yet.
    (void)MTracker->readReg(SrcSubReg);
    LocIdx SrcL = MTracker->getRegMLoc(SrcSubReg);
    assert(SrcL.asU64());
    (void)MTracker->readReg(DstSubReg);
    LocIdx DstL = MTracker->getRegMLoc(DstSubReg);
    assert(DstL.asU64());
    (void)DstL;
    ValueIDNum CpyValue = {SrcValue.getBlock(), SrcValue.getInst(), SrcL};

    MTracker->setReg(DstSubReg, CpyValue);
  }
}

bool MachineLocTracking::isSpillInstruction(const MachineInstr &MI,
                                          MachineFunction *MF) {
  // TODO: Handle multiple stores folded into one.
  if (!MI.hasOneMemOperand())
    return false;

  if (!MI.getSpillSize(TII) && !MI.getFoldedSpillSize(TII))
    return false; // This is not a spill instruction, since no valid size was
                  // returned from either function.

  return true;
}

bool MachineLocTracking::isLocationSpill(const MachineInstr &MI,
                                       MachineFunction *MF, unsigned &Reg) {
  if (!isSpillInstruction(MI, MF))
    return false;

  auto isKilledReg = [&](const MachineOperand MO, unsigned &Reg) {
    if (!MO.isReg() || !MO.isUse()) {
      Reg = 0;
      return false;
    }
    Reg = MO.getReg();
    return MO.isKill();
  };

  for (const MachineOperand &MO : MI.operands()) {
    // In a spill instruction generated by the InlineSpiller the spilled
    // register has its kill flag set.
    if (isKilledReg(MO, Reg))
      return true;
    if (Reg != 0) {
      // Check whether next instruction kills the spilled register.
      // FIXME: Current solution does not cover search for killed register in
      // bundles and instructions further down the chain.
      auto NextI = std::next(MI.getIterator());
      // Skip next instruction that points to basic block end iterator.
      if (MI.getParent()->end() == NextI)
        continue;
      unsigned RegNext;
      for (const MachineOperand &MONext : NextI->operands()) {
        // Return true if we came across the register from the
        // previous spill instruction that is killed in NextI.
        if (isKilledReg(MONext, RegNext) && RegNext == Reg)
          return true;
      }
    }
  }
  // Return false if we didn't find spilled register.
  return false;
}

Optional<SpillLoc>
MachineLocTracking::isRestoreInstruction(const MachineInstr &MI,
                                       MachineFunction *MF, unsigned &Reg) {
  if (!MI.hasOneMemOperand())
    return None;

  // FIXME: Handle folded restore instructions with more than one memory
  // operand.
  if (MI.getRestoreSize(TII)) {
    Reg = MI.getOperand(0).getReg();
    return extractSpillBaseRegAndOffset(MI);
  }
  return None;
}

bool MachineLocTracking::transferSpillOrRestoreInst(MachineInstr &MI) {
  MachineFunction *MF = MI.getMF();
  unsigned Reg;
  Optional<SpillLoc> Loc;

  // Try to recognise spill and restore instructions that may transfer a value.
  if (isLocationSpill(MI, MF, Reg)) {
    Loc = extractSpillBaseRegAndOffset(MI);
    auto ValueID = MTracker->readReg(Reg);

    // If the location is empty, produce a phi, signify it's the live-in value.
    if (ValueID.getLoc() == 0)
      ValueID = {CurBB, 0, MTracker->getRegMLoc(Reg)};

    MTracker->setSpill(*Loc, ValueID);
    auto OptSpillLocIdx = MTracker->getSpillMLoc(*Loc);
    assert(OptSpillLocIdx && "Spill slot set but has no LocIdx?");
  } else {
    if (!(Loc = isRestoreInstruction(MI, MF, Reg)))
      return false;

    // Is there a value to be restored?
    auto OptValueID = MTracker->readSpill(*Loc);
    if (OptValueID) {
      ValueIDNum ValueID = *OptValueID;
      // XXX -- can we recover sub-registers of this value? Until we can, first
      // overwrite all defs of the register being restored to.
      for (MCRegAliasIterator RAI(Reg, TRI, true); RAI.isValid(); ++RAI)
        MTracker->defReg(*RAI, CurBB, CurInst);

      // Now override the reg we're restoring to.
      MTracker->setReg(Reg, ValueID);
    } else {
      // There isn't anything in the location; not clear if this is a code path
      // that still runs. Def this register anyway just in case.
      for (MCRegAliasIterator RAI(Reg, TRI, true); RAI.isValid(); ++RAI)
        MTracker->defReg(*RAI, CurBB, CurInst);

      // Force the spill slot to be tracked.
      LocIdx L = MTracker->getOrTrackSpillLoc(*Loc);

      // Set the restored value to be a machine phi number, signifying that it's
      // whatever the spills live-in value is in this block. Definitely has
      // a LocIdx due to the setSpill above.
      ValueIDNum ValueID = {CurBB, 0, L};
      MTracker->setReg(Reg, ValueID);
      MTracker->setSpill(*Loc, ValueID);
    }
  }
  return true;
}

bool MachineLocTracking::transferRegisterCopy(MachineInstr &MI) {
  auto DestSrc = TII->isCopyInstr(MI);
  if (!DestSrc)
    return false;

  const MachineOperand *DestRegOp = DestSrc->Destination;
  const MachineOperand *SrcRegOp = DestSrc->Source;

  Register SrcReg = SrcRegOp->getReg();
  Register DestReg = DestRegOp->getReg();

  // Ignore identity copies. Yep, these make it as far as LiveDebugValues.
  if (SrcReg == DestReg)
    return true;

  // Copy MTracker info, including subregs if available.
  MachineLocTracking::performCopy(SrcReg, DestReg);

  // FIXME: Should we def the src-reg?
  // MTracker->defReg(SrcReg, CurBB, CurInst);

  return true;
}

void MachineLocTracking::process(MachineInstr &MI) {
  if (transferRegisterCopy(MI))
    return;
  if (transferSpillOrRestoreInst(MI))
    return;
  transferRegisterDef(MI);
}

void MachineLocTracking::produceMLocTransferFunction(
    MachineFunction &MF, SmallVectorImpl<MLocTransferMap> &MLocTransfer,
    unsigned MaxNumBlocks) {
  // Because we try to optimize around register mask operands by ignoring regs
  // that aren't currently tracked, we set up something ugly for later: RegMask
  // operands that are seen earlier than the first use of a register, still need
  // to clobber that register in the transfer function. But this information
  // isn't actively recorded. Instead, we track each RegMask used in each block,
  // and accumulated the clobbered but untracked registers in each block into
  // the following bitvector. Later, if new values are tracked, we can add
  // appropriate clobbers.
  SmallVector<BitVector, 32> BlockMasks;
  BlockMasks.resize(MaxNumBlocks);

  // Reserve one bit per register for the masks described above.
  unsigned BVWords = MachineOperand::getRegMaskSize(TRI->getNumRegs());
  for (auto &BV : BlockMasks)
    BV.resize(TRI->getNumRegs(), true);

  // Step through all instructions and inhale the transfer function.
  for (auto &MBB : MF) {
    // Object fields that are read by trackers to know where we are in the
    // function.
    CurBB = MBB.getNumber();
    CurInst = 1;

    // Set all machine locations to a PHI value. For transfer function
    // production only, this signifies the live-in value to the block.
    MTracker->reset();
    MTracker->setMPhis(CurBB);

    // Step through each instruction in this block.
    for (auto &MI : MBB) {
      process(MI);

      // Create a map from the instruction number (if present) to the
      // MachineInstr and its position.
      if (uint64_t InstrNo = MI.peekDebugInstrNum()) {
        auto InstrAndPos = std::make_pair(&MI, CurInst);
        auto InsertResult =
            DebugInstrNumToInstr.insert(std::make_pair(InstrNo, InstrAndPos));

        // There should never be duplicate instruction numbers.
        assert(InsertResult.second);
        (void)InsertResult;
      }

      ++CurInst;
    }

    // Produce the transfer function, a map of machine location to new value. If
    // any machine location has the live-in phi value from the start of the
    // block, it's live-through and doesn't need recording in the transfer
    // function.
    for (auto Location : MTracker->locations()) {
      LocIdx Idx = Location.Idx;
      ValueIDNum &P = Location.Value;
      if (P.isPHI() && P.getLoc() == Idx.asU64())
        continue;

      // Insert-or-update.
      auto &TransferMap = MLocTransfer[CurBB];
      auto Result = TransferMap.insert(std::make_pair(Idx.asU64(), P));
      if (!Result.second)
        Result.first->second = P;
    }

    // Accumulate any bitmask operands into the clobberred reg mask for this
    // block.
    for (auto &P : MTracker->Masks) {
      BlockMasks[CurBB].clearBitsNotInMask(P.first->getRegMask(), BVWords);
    }
  }

  // Compute a bitvector of all the registers that are tracked in this block.
  const TargetLowering *TLI = MF.getSubtarget().getTargetLowering();
  Register SP = TLI->getStackPointerRegisterToSaveRestore();
  BitVector UsedRegs(TRI->getNumRegs());
  for (auto Location : MTracker->locations()) {
    unsigned ID = MTracker->LocIdxToLocID[Location.Idx];
    if (ID >= TRI->getNumRegs() || ID == SP)
      continue;
    UsedRegs.set(ID);
  }

  // Check that any regmask-clobber of a register that gets tracked, is not
  // live-through in the transfer function. It needs to be clobbered at the
  // very least.
  for (unsigned int I = 0; I < MaxNumBlocks; ++I) {
    BitVector &BV = BlockMasks[I];
    BV.flip();
    BV &= UsedRegs;
    // This produces all the bits that we clobber, but also use. Check that
    // they're all clobbered or at least set in the designated transfer
    // elem.
    for (unsigned Bit : BV.set_bits()) {
      unsigned ID = MTracker->getLocID(Bit, false);
      LocIdx Idx = MTracker->LocIDToLocIdx[ID];
      auto &TransferMap = MLocTransfer[I];

      // Install a value representing the fact that this location is effectively
      // written to in this block. As there's no reserved value, instead use
      // a value number that is never generated. Pick the value number for the
      // first instruction in the block, def'ing this location, which we know
      // this block never used anyway.
      ValueIDNum NotGeneratedNum = ValueIDNum(I, 1, Idx);
      auto Result =
        TransferMap.insert(std::make_pair(Idx.asU64(), NotGeneratedNum));
      if (!Result.second) {
        ValueIDNum &ValueID = Result.first->second;
        if (ValueID.getBlock() == I && ValueID.isPHI())
          // It was left as live-through. Set it to clobbered.
          ValueID = NotGeneratedNum;
      }
    }
  }
}

void MachineLocTracking::printMLocTransferFunction(
    MachineFunction &MF, SmallVectorImpl<MLocTransferMap> &MLocTransfer,
    unsigned MaxNumBlocks) {
  llvm::dbgs() << "*** Transfer function for each basic block ***\n";
  for (auto &MBB : MF) {
    if (MBB.getName() != "")
      llvm::dbgs() << "** BB: " << MBB.getName() << "\n";
    else
      llvm::dbgs() << "** BB: " << MBB.getNumber() << "\n";
    unsigned BBNum = MBB.getNumber();
    auto &TransferMap = MLocTransfer[BBNum];
    for (auto &P : TransferMap) {
      std::string Location = MTracker->LocIdxToName(P.first);
      std::string Value = MTracker->IDAsString(P.second);
      llvm::dbgs() << Location << " = " << Value << "\n";
    }
    llvm::dbgs() << "\n";
  }
}

#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
void MachineLocTracking::dump_mloc_transfer(
    const MLocTransferMap &mloc_transfer) const {
  for (auto &P : mloc_transfer) {
    std::string foo = MTracker->LocIdxToName(P.first);
    std::string bar = MTracker->IDAsString(P.second);
    dbgs() << "Loc " << foo << " --> " << bar << "\n";
  }
}
#endif

void MachineLocTracking::initialSetup(MachineFunction &MF) {
  // Compute mappings of block <=> RPO order.
  ReversePostOrderTraversal<MachineFunction *> RPOT(&MF);
  unsigned int RPONumber = 0;
  for (auto RI = RPOT.begin(), RE = RPOT.end(); RI != RE; ++RI) {
    OrderToBB[RPONumber] = *RI;
    BBToOrder[*RI] = RPONumber;
    BBNumToRPO[(*RI)->getNumber()] = RPONumber;
    ++RPONumber;
  }
}

std::tuple<bool, bool>
MachineLocTracking::mlocJoin(MachineBasicBlock &MBB,
                             SmallPtrSet<const MachineBasicBlock *, 16> &Visited,
                             ValueIDNum **OutLocs, ValueIDNum *InLocs) {
  LLVM_DEBUG(dbgs() << "join MBB: " << MBB.getNumber() << "\n");
  bool Changed = false;
  bool DowngradeOccurred = false;

  // Collect predecessors that have been visited. Anything that hasn't been
  // visited yet is a backedge on the first iteration, and the meet of it's
  // lattice value for all locations will be unaffected.
  SmallVector<const MachineBasicBlock *, 8> BlockOrders;
  for (auto Pred : MBB.predecessors()) {
    if (Visited.count(Pred)) {
      BlockOrders.push_back(Pred);
    }
  }

  // Visit predecessors in RPOT order.
  auto Cmp = [&](const MachineBasicBlock *A, const MachineBasicBlock *B) {
    return BBToOrder.find(A)->second < BBToOrder.find(B)->second;
  };
  llvm::sort(BlockOrders.begin(), BlockOrders.end(), Cmp);

  // Skip entry block.
  if (BlockOrders.size() == 0)
    return std::tuple<bool, bool>(false, false);

  // Step through all machine locations, then look at each predecessor and
  // detect disagreements.
  unsigned ThisBlockRPO = BBToOrder.find(&MBB)->second;
  for (auto Location : MTracker->locations()) {
    LocIdx Idx = Location.Idx;
    // Pick out the first predecessors live-out value for this location. It's
    // guaranteed to be not a backedge, as we order by RPO.
    ValueIDNum BaseVal = OutLocs[BlockOrders[0]->getNumber()][Idx.asU64()];

    // Some flags for whether there's a disagreement, and whether it's a
    // disagreement with a backedge or not.
    bool Disagree = false;
    bool NonBackEdgeDisagree = false;

    // Loop around everything that wasn't 'base'.
    for (unsigned int I = 1; I < BlockOrders.size(); ++I) {
      auto *MBB = BlockOrders[I];
      if (BaseVal != OutLocs[MBB->getNumber()][Idx.asU64()]) {
        // Live-out of a predecessor disagrees with the first predecessor.
        Disagree = true;

        // Test whether it's a disagreemnt in the backedges or not.
        if (BBToOrder.find(MBB)->second < ThisBlockRPO) // might be self b/e
          NonBackEdgeDisagree = true;
      }
    }

    bool OverRide = false;
    if (Disagree && !NonBackEdgeDisagree) {
      // Only the backedges disagree. Consider demoting the livein
      // lattice value, as per the file level comment. The value we consider
      // demoting to is the value that the non-backedge predecessors agree on.
      // The order of values is that non-PHIs are \top, a PHI at this block
      // \bot, and phis between the two are ordered by their RPO number.
      // If there's no agreement, or we've already demoted to this PHI value
      // before, replace with a PHI value at this block.

      // Calculate order numbers: zero means normal def, nonzero means RPO
      // number.
      unsigned BaseBlockRPONum = BBNumToRPO[BaseVal.getBlock()] + 1;
      if (!BaseVal.isPHI())
        BaseBlockRPONum = 0;

      ValueIDNum &InLocID = InLocs[Idx.asU64()];
      unsigned InLocRPONum = BBNumToRPO[InLocID.getBlock()] + 1;
      if (!InLocID.isPHI())
        InLocRPONum = 0;

      // Should we ignore the disagreeing backedges, and override with the
      // value the other predecessors agree on (in "base")?
      unsigned ThisBlockRPONum = BBNumToRPO[MBB.getNumber()] + 1;
      if (BaseBlockRPONum > InLocRPONum && BaseBlockRPONum < ThisBlockRPONum) {
        // Override.
        OverRide = true;
        DowngradeOccurred = true;
      }
    }
    // else: if we disagree in the non-backedges, then this is definitely
    // a control flow merge where different values merge. Make it a PHI.

    // Generate a phi...
    ValueIDNum PHI = {(uint64_t)MBB.getNumber(), 0, Idx};
    ValueIDNum NewVal = (Disagree && !OverRide) ? PHI : BaseVal;
    if (InLocs[Idx.asU64()] != NewVal) {
      Changed |= true;
      InLocs[Idx.asU64()] = NewVal;
    }
  }

  // Uhhhhhh, reimplement NumInserted and NumRemoved pls.
  return std::tuple<bool, bool>(Changed, DowngradeOccurred);
}

void MachineLocTracking::mlocDataflow(
    ValueIDNum **MInLocs, ValueIDNum **MOutLocs,
    SmallVectorImpl<MLocTransferMap> &MLocTransfer) {
  std::priority_queue<unsigned int, std::vector<unsigned int>,
                      std::greater<unsigned int>>
      Worklist, Pending;

  // We track what is on the current and pending worklist to avoid inserting
  // the same thing twice. We could avoid this with a custom priority queue,
  // but this is probably not worth it.
  SmallPtrSet<MachineBasicBlock *, 16> OnPending, OnWorklist;

  // Initialize worklist with every block to be visited.
  for (unsigned int I = 0; I < BBToOrder.size(); ++I) {
    Worklist.push(I);
    OnWorklist.insert(OrderToBB[I]);
  }

  MTracker->reset();

  // Set inlocs for entry block -- each as a PHI at the entry block. Represents
  // the incoming value to the function.
  MTracker->setMPhis(0);
  for (auto Location : MTracker->locations())
    MInLocs[0][Location.Idx.asU64()] = Location.Value;

  SmallPtrSet<const MachineBasicBlock *, 16> Visited;
  while (!Worklist.empty() || !Pending.empty()) {
    // Vector for storing the evaluated block transfer function.
    SmallVector<std::pair<LocIdx, ValueIDNum>, 32> ToRemap;

    while (!Worklist.empty()) {
      MachineBasicBlock *MBB = OrderToBB[Worklist.top()];
      CurBB = MBB->getNumber();
      Worklist.pop();

      // Join the values in all predecessor blocks.
      bool InLocsChanged, DowngradeOccurred;
      std::tie(InLocsChanged, DowngradeOccurred) =
          mlocJoin(*MBB, Visited, MOutLocs, MInLocs[CurBB]);
      InLocsChanged |= Visited.insert(MBB).second;

      // If a downgrade occurred, book us in for re-examination on the next
      // iteration.
      if (DowngradeOccurred && OnPending.insert(MBB).second)
        Pending.push(BBToOrder[MBB]);

      // Don't examine transfer function if we've visited this loc at least
      // once, and inlocs haven't changed.
      if (!InLocsChanged)
        continue;

      // Load the current set of live-ins into MLocTracker.
      MTracker->loadFromArray(MInLocs[CurBB], CurBB);

      // Each element of the transfer function can be a new def, or a read of
      // a live-in value. Evaluate each element, and store to "ToRemap".
      ToRemap.clear();
      for (auto &P : MLocTransfer[CurBB]) {
        if (P.second.getBlock() == CurBB && P.second.isPHI()) {
          // This is a movement of whatever was live in. Read it.
          ValueIDNum NewID = MTracker->getNumAtPos(P.second.getLoc());
          ToRemap.push_back(std::make_pair(P.first, NewID));
        } else {
          // It's a def. Just set it.
          assert(P.second.getBlock() == CurBB);
          ToRemap.push_back(std::make_pair(P.first, P.second));
        }
      }

      // Commit the transfer function changes into mloc tracker, which
      // transforms the contents of the MLocTracker into the live-outs.
      for (auto &P : ToRemap)
        MTracker->setMLoc(P.first, P.second);

      // Now copy out-locs from mloc tracker into out-loc vector, checking
      // whether changes have occurred. These changes can have come from both
      // the transfer function, and mlocJoin.
      bool OLChanged = false;
      for (auto Location : MTracker->locations()) {
        OLChanged |= MOutLocs[CurBB][Location.Idx.asU64()] != Location.Value;
        MOutLocs[CurBB][Location.Idx.asU64()] = Location.Value;
      }

      MTracker->reset();

      // No need to examine successors again if out-locs didn't change.
      if (!OLChanged)
        continue;

      // All successors should be visited: put any back-edges on the pending
      // list for the next dataflow iteration, and any other successors to be
      // visited this iteration, if they're not going to be already.
      for (auto s : MBB->successors()) {
        // Does branching to this successor represent a back-edge?
        if (BBToOrder[s] > BBToOrder[MBB]) {
          // No: visit it during this dataflow iteration.
          if (OnWorklist.insert(s).second)
            Worklist.push(BBToOrder[s]);
        } else {
          // Yes: visit it on the next iteration.
          if (OnPending.insert(s).second)
            Pending.push(BBToOrder[s]);
        }
      }
    }

    Worklist.swap(Pending);
    std::swap(OnPending, OnWorklist);
    OnPending.clear();
    // At this point, pending must be empty, since it was just the empty
    // worklist
    assert(Pending.empty() && "Pending should be empty");
  }

  // Once all the live-ins don't change on mlocJoin(), we've reached a
  // fixedpoint.
}

bool MachineLocTracking::run(MachineFunction &MF) {
  LLVM_DEBUG(llvm::dbgs() << "****** Machine Location Tracking for function: "
                          << MF.getName() << "\n");

  TRI = MF.getSubtarget().getRegisterInfo();
  TII = MF.getSubtarget().getInstrInfo();
  TFI = MF.getSubtarget().getFrameLowering();
  TFI->getCalleeSaves(MF, CalleeSavedRegs);

  MTracker =
      new MLocTracker(MF, *TII, *TRI, *MF.getSubtarget().getTargetLowering());

  SmallVector<MLocTransferMap, 32> MLocTransfer;

  int MaxNumBlocks = -1;
  for (auto &MBB : MF)
    MaxNumBlocks = std::max(MBB.getNumber(), MaxNumBlocks);
  assert(MaxNumBlocks >= 0);
  ++MaxNumBlocks;

  MLocTransfer.resize(MaxNumBlocks);

  initialSetup(MF);

  produceMLocTransferFunction(MF, MLocTransfer, MaxNumBlocks);
  // Used for debugging purposes.
  LLVM_DEBUG(printMLocTransferFunction(MF, MLocTransfer, MaxNumBlocks));

  // Allocate and initialize two array-of-arrays for the live-in and live-out
  // machine values. The outer dimension is the block number; while the inner
  // dimension is a LocIdx from MLocTracker.
  ValueIDNum **MOutLocs = new ValueIDNum *[MaxNumBlocks];
  ValueIDNum **MInLocs = new ValueIDNum *[MaxNumBlocks];
  unsigned NumLocs = MTracker->getNumLocs();
  for (int i = 0; i < MaxNumBlocks; ++i) {
    MOutLocs[i] = new ValueIDNum[NumLocs];
    MInLocs[i] = new ValueIDNum[NumLocs];
  }

  // Solve the machine value dataflow problem using the MLocTransfer function,
  // storing the computed live-ins / live-outs into the array-of-arrays. We use
  // both live-ins and live-outs for decision making in the variable value
  // dataflow problem.
  mlocDataflow(MInLocs, MOutLocs, MLocTransfer);

  return true;
}
