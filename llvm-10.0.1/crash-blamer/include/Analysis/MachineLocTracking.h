//===- TaintAnalysis.h - Catch the source of a crash ----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/UniqueVector.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/Register.h"
#include "llvm/CodeGen/TargetFrameLowering.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetLowering.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#include <map>

using namespace llvm;

namespace {

// The location at which a spilled value resides. It consists of a register and
// an offset.
struct SpillLoc {
  unsigned SpillBase;
  int SpillOffset;
  bool operator==(const SpillLoc &Other) const {
    return std::tie(SpillBase, SpillOffset) ==
           std::tie(Other.SpillBase, Other.SpillOffset);
  }
  bool operator<(const SpillLoc &Other) const {
    return std::tie(SpillBase, SpillOffset) <
           std::tie(Other.SpillBase, Other.SpillOffset);
  }
};

class LocIdx {
  unsigned Location;

  // Default constructor is private, initializing to an illegal location number.
  // Use only for "not an entry" elements in IndexedMaps.
  LocIdx() : Location(UINT_MAX) { }

public:
  #define NUM_LOC_BITS 24
  LocIdx(unsigned L) : Location(L) {
    assert(L < (1 << NUM_LOC_BITS) && "Machine locations must fit in 24 bits");
  }

  static LocIdx MakeIllegalLoc() {
    return LocIdx();
  }

  bool isIllegal() const {
    return Location == UINT_MAX;
  }

  uint64_t asU64() const {
    return Location;
  }

  bool operator==(unsigned L) const {
    return Location == L;
  }

  bool operator==(const LocIdx &L) const {
    return Location == L.Location;
  }

  bool operator!=(unsigned L) const {
    return !(*this == L);
  }

  bool operator!=(const LocIdx &L) const {
    return !(*this == L);
  }

  bool operator<(const LocIdx &Other) const {
    return Location < Other.Location;
  }
};

class LocIdxToIndexFunctor {
public:
  using argument_type = LocIdx;
  unsigned operator()(const LocIdx &L) const {
    return L.asU64();
  }
};

/// Unique identifier for a value defined by an instruction, as a value type.
/// Casts back and forth to a uint64_t. Probably replacable with something less
/// bit-constrained. Each value identifies the instruction and machine location
/// where the value is defined, although there may be no corresponding machine
/// operand for it (ex: regmasks clobbering values). The instructions are
/// one-based, and definitions that are PHIs have instruction number zero.
///
/// The obvious limits of a 1M block function or 1M instruction blocks are
/// problematic; but by that point we should probably have bailed out of
/// trying to analyse the function.
class ValueIDNum {
  uint64_t BlockNo : 20;         /// The block where the def happens.
  uint64_t InstNo : 20;          /// The Instruction where the def happens.
                                 /// One based, is distance from start of block.
  uint64_t LocNo : NUM_LOC_BITS; /// The machine location where the def happens.

public:
  // XXX -- temporarily enabled while the live-in / live-out tables are moved
  // to something more type-y
  ValueIDNum() : BlockNo(0xFFFFF),
                 InstNo(0xFFFFF),
                 LocNo(0xFFFFFF) { }

  ValueIDNum(uint64_t Block, uint64_t Inst, uint64_t Loc)
    : BlockNo(Block), InstNo(Inst), LocNo(Loc) { }

  ValueIDNum(uint64_t Block, uint64_t Inst, LocIdx Loc)
    : BlockNo(Block), InstNo(Inst), LocNo(Loc.asU64()) { }

  uint64_t getBlock() const { return BlockNo; }
  uint64_t getInst() const { return InstNo; }
  uint64_t getLoc() const { return LocNo; }
  bool isPHI() const { return InstNo == 0; }

  uint64_t asU64() const {
    uint64_t TmpBlock = BlockNo;
    uint64_t TmpInst = InstNo;
    return TmpBlock << 44ull | TmpInst << NUM_LOC_BITS | LocNo;
  }

  static ValueIDNum fromU64(uint64_t v) {
    uint64_t L = (v & 0x3FFF);
    return {v >> 44ull, ((v >> NUM_LOC_BITS) & 0xFFFFF), L};
  }

  bool operator<(const ValueIDNum &Other) const {
    return asU64() < Other.asU64();
  }

  bool operator==(const ValueIDNum &Other) const {
    return std::tie(BlockNo, InstNo, LocNo) ==
           std::tie(Other.BlockNo, Other.InstNo, Other.LocNo);
  }

  bool operator!=(const ValueIDNum &Other) const { return !(*this == Other); }

  std::string asString(const std::string &mlocname) const {
    return Twine("Value{bb: ")
        .concat(Twine(BlockNo).concat(
            Twine(", inst: ")
                .concat((InstNo ? Twine(InstNo) : Twine("live-in"))
                            .concat(Twine(", loc: ").concat(Twine(mlocname)))
                            .concat(Twine("}")))))
        .str();
  }

  static ValueIDNum EmptyValue;
};

} // end anonymous namespace

namespace {
/// Tracker for what values are in machine locations. Listens to the Things
/// being Done by various instructions, and maintains a table of what machine
/// locations have what values (as defined by a ValueIDNum).
///
/// There are potentially a much larger number of machine locations on the
/// target machine than the actual working-set size of the function. On x86 for
/// example, we're extremely unlikely to want to track values through control
/// or debug registers. To avoid doing so, MLocTracker has several layers of
/// indirection going on, with two kinds of ``location'':
///  * A LocID uniquely identifies a register or spill location, with a
///    predictable value.
///  * A LocIdx is a key (in the database sense) for a LocID and a ValueIDNum.
/// Whenever a location is def'd or used by a MachineInstr, we automagically
/// create a new LocIdx for a location, but not otherwise. This ensures we only
/// account for locations that are actually used or defined. The cost is another
/// vector lookup (of LocID -> LocIdx) over any other implementation. This is
/// fairly cheap, and the compiler tries to reduce the working-set at any one
/// time in the function anyway.
///
/// Register mask operands completely blow this out of the water; I've just
/// piled hacks on top of hacks to get around that.
class MLocTracker {
public:
  MachineFunction &MF;
  const TargetInstrInfo &TII;
  const TargetRegisterInfo &TRI;
  const TargetLowering &TLI;

  /// IndexedMap type, mapping from LocIdx to ValueIDNum.
  using LocToValueType = IndexedMap<ValueIDNum, LocIdxToIndexFunctor>;

  /// Map of LocIdxes to the ValueIDNums that they store. This is tightly
  /// packed, entries only exist for locations that are being tracked.
  LocToValueType LocIdxToIDNum;

  /// "Map" of machine location IDs (i.e., raw register or spill number) to the
  /// LocIdx key / number for that location. There are always at least as many
  /// as the number of registers on the target -- if the value in the register
  /// is not being tracked, then the LocIdx value will be zero. New entries are
  /// appended if a new spill slot begins being tracked.
  /// This, and the corresponding reverse map persist for the analysis of the
  /// whole function, and is necessarying for decoding various vectors of
  /// values.
  std::vector<LocIdx> LocIDToLocIdx;

  /// Inverse map of LocIDToLocIdx.
  IndexedMap<unsigned, LocIdxToIndexFunctor> LocIdxToLocID;

  /// Unique-ification of spill slots. Used to number them -- their LocID
  /// number is the index in SpillLocs minus one plus NumRegs.
  UniqueVector<SpillLoc> SpillLocs;

  // If we discover a new machine location, assign it an mphi with this
  // block number.
  unsigned CurBB;

  /// Cached local copy of the number of registers the target has.
  unsigned NumRegs;

  /// Collection of register mask operands that have been observed. Second part
  /// of pair indicates the instruction that they happened in. Used to
  /// reconstruct where defs happened if we start tracking a location later
  /// on.
  SmallVector<std::pair<const MachineOperand *, unsigned>, 32> Masks;

  /// Iterator for locations and the values they contain. Dereferencing
  /// produces a struct/pair containing the LocIdx key for this location,
  /// and a reference to the value currently stored. Simplifies the process
  /// of seeking a particular location.
  class MLocIterator {
    LocToValueType &ValueMap;
    LocIdx Idx;

  public:
    class value_type {
      public:
      value_type(LocIdx Idx, ValueIDNum &Value) : Idx(Idx), Value(Value) { }
      const LocIdx Idx;  /// Read-only index of this location.
      ValueIDNum &Value; /// Reference to the stored value at this location.
    };

    MLocIterator(LocToValueType &ValueMap, LocIdx Idx)
      : ValueMap(ValueMap), Idx(Idx) { }

    bool operator==(const MLocIterator &Other) const {
      assert(&ValueMap == &Other.ValueMap);
      return Idx == Other.Idx;
    }

    bool operator!=(const MLocIterator &Other) const {
      return !(*this == Other);
    }

    void operator++() {
      Idx = LocIdx(Idx.asU64() + 1);
    }

    value_type operator*() {
      return value_type(Idx, ValueMap[LocIdx(Idx)]);
    }
  };

  MLocTracker(MachineFunction &MF, const TargetInstrInfo &TII,
              const TargetRegisterInfo &TRI, const TargetLowering &TLI)
      : MF(MF), TII(TII), TRI(TRI), TLI(TLI),
        LocIdxToIDNum(ValueIDNum::EmptyValue),
        LocIdxToLocID(0) {
    NumRegs = TRI.getNumRegs();
    reset();
    LocIDToLocIdx.resize(NumRegs, LocIdx::MakeIllegalLoc());
    assert(NumRegs < (1u << NUM_LOC_BITS)); // Detect bit packing failure

    // Always track SP. This avoids the implicit clobbering caused by regmasks
    // from affectings its values. (LiveDebugValues disbelieves calls and
    // regmasks that claim to clobber SP).
    Register SP = TLI.getStackPointerRegisterToSaveRestore();
    if (SP) {
      unsigned ID = getLocID(SP, false);
      (void)lookupOrTrackRegister(ID);
    }
  }

  /// Produce location ID number for indexing LocIDToLocIdx. Takes the register
  /// or spill number, and flag for whether it's a spill or not.
  unsigned getLocID(Register RegOrSpill, bool isSpill) {
    return (isSpill) ? RegOrSpill.id() + NumRegs - 1 : RegOrSpill.id();
  }

  /// Accessor for reading the value at Idx.
  ValueIDNum getNumAtPos(LocIdx Idx) const {
    assert(Idx.asU64() < LocIdxToIDNum.size());
    return LocIdxToIDNum[Idx];
  }

  unsigned getNumLocs(void) const { return LocIdxToIDNum.size(); }

  /// Reset all locations to contain a PHI value at the designated block. Used
  /// sometimes for actual PHI values, othertimes to indicate the block entry
  /// value (before any more information is known).
  void setMPhis(unsigned NewCurBB) {
    CurBB = NewCurBB;
    for (auto Location : locations())
      Location.Value = {CurBB, 0, Location.Idx};
  }

  /// Load values for each location from array of ValueIDNums. Take current
  /// bbnum just in case we read a value from a hitherto untouched register.
  void loadFromArray(ValueIDNum *Locs, unsigned NewCurBB) {
    CurBB = NewCurBB;
    // Iterate over all tracked locations, and load each locations live-in
    // value into our local index.
    for (auto Location : locations())
      Location.Value = Locs[Location.Idx.asU64()];
  }

  /// Wipe any un-necessary location records after traversing a block.
  void reset(void) {
    // We could reset all the location values too; however either loadFromArray
    // or setMPhis should be called before this object is re-used. Just
    // clear Masks, they're definitely not needed.
    Masks.clear();
  }

  /// Clear all data. Destroys the LocID <=> LocIdx map, which makes most of
  /// the information in this pass uninterpretable.
  void clear(void) {
    reset();
    LocIDToLocIdx.clear();
    LocIdxToLocID.clear();
    LocIdxToIDNum.clear();
    //SpillLocs.reset(); XXX UniqueVector::reset assumes a SpillLoc casts from 0
    SpillLocs = decltype(SpillLocs)();

    LocIDToLocIdx.resize(NumRegs, LocIdx::MakeIllegalLoc());
  }

  /// Set a locaiton to a certain value.
  void setMLoc(LocIdx L, ValueIDNum Num) {
    assert(L.asU64() < LocIdxToIDNum.size());
    LocIdxToIDNum[L] = Num;
  }

  /// Create a LocIdx for an untracked register ID. Initialize it to either an
  /// mphi value representing a live-in, or a recent register mask clobber.
  LocIdx trackRegister(unsigned ID) {
    assert(ID != 0);
    LocIdx NewIdx = LocIdx(LocIdxToIDNum.size());
    LocIdxToIDNum.grow(NewIdx);
    LocIdxToLocID.grow(NewIdx);

    // Default: it's an mphi.
    ValueIDNum ValNum = {CurBB, 0, NewIdx};
    // Was this reg ever touched by a regmask?
    for (const auto &MaskPair : reverse(Masks)) {
      if (MaskPair.first->clobbersPhysReg(ID)) {
        // There was an earlier def we skipped.
        ValNum = {CurBB, MaskPair.second, NewIdx};
        break;
      }
    }

    LocIdxToIDNum[NewIdx] = ValNum;
    LocIdxToLocID[NewIdx] = ID;
    return NewIdx;
  }

  LocIdx lookupOrTrackRegister(unsigned ID) {
    LocIdx &Index = LocIDToLocIdx[ID];
    if (Index.isIllegal())
      Index = trackRegister(ID);
    return Index;
  }

  /// Record a definition of the specified register at the given block / inst.
  /// This doesn't take a ValueIDNum, because the definition and its location
  /// are synonymous.
  void defReg(Register R, unsigned BB, unsigned Inst) {
    unsigned ID = getLocID(R, false);
    LocIdx Idx = lookupOrTrackRegister(ID);
    ValueIDNum ValueID = {BB, Inst, Idx};
    LocIdxToIDNum[Idx] = ValueID;
  }

  /// Set a register to a value number. To be used if the value number is
  /// known in advance.
  void setReg(Register R, ValueIDNum ValueID) {
    unsigned ID = getLocID(R, false);
    LocIdx Idx = lookupOrTrackRegister(ID);
    LocIdxToIDNum[Idx] = ValueID;
  }

  ValueIDNum readReg(Register R) {
    unsigned ID = getLocID(R, false);
    LocIdx Idx = lookupOrTrackRegister(ID);
    return LocIdxToIDNum[Idx];
  }

  /// Reset a register value to zero / empty. Needed to replicate the
  /// VarLoc implementation where a copy to/from a register effectively
  /// clears the contents of the source register. (Values can only have one
  ///  machine location in VarLocBasedImpl).
  void wipeRegister(Register R) {
    unsigned ID = getLocID(R, false);
    LocIdx Idx = LocIDToLocIdx[ID];
    LocIdxToIDNum[Idx] = ValueIDNum::EmptyValue;
  }

  /// Determine the LocIdx of an existing register.
  LocIdx getRegMLoc(Register R) {
    unsigned ID = getLocID(R, false);
    return LocIDToLocIdx[ID];
  }

  /// Record a RegMask operand being executed. Defs any register we currently
  /// track, stores a pointer to the mask in case we have to account for it
  /// later.
  void writeRegMask(const MachineOperand *MO, unsigned CurBB, unsigned InstID) {
    // Ensure SP exists, so that we don't override it later.
    Register SP = TLI.getStackPointerRegisterToSaveRestore();

    // Def any register we track have that isn't preserved. The regmask
    // terminates the liveness of a register, meaning its value can't be
    // relied upon -- we represent this by giving it a new value.
    for (auto Location : locations()) {
      unsigned ID = LocIdxToLocID[Location.Idx];
      // Don't clobber SP, even if the mask says it's clobbered.
      if (ID < NumRegs && ID != SP && MO->clobbersPhysReg(ID))
        defReg(ID, CurBB, InstID);
    }
    Masks.push_back(std::make_pair(MO, InstID));
  }

  /// Find LocIdx for SpillLoc \p L, creating a new one if it's not tracked.
  LocIdx getOrTrackSpillLoc(SpillLoc L) {
    unsigned SpillID = SpillLocs.idFor(L);
    if (SpillID == 0) {
      SpillID = SpillLocs.insert(L);
      unsigned L = getLocID(SpillID, true);
      LocIdx Idx = LocIdx(LocIdxToIDNum.size()); // New idx
      LocIdxToIDNum.grow(Idx);
      LocIdxToLocID.grow(Idx);
      LocIDToLocIdx.push_back(Idx);
      LocIdxToLocID[Idx] = L;
      return Idx;
    } else {
      unsigned L = getLocID(SpillID, true);
      LocIdx Idx = LocIDToLocIdx[L];
      return Idx;
    }
  }

  /// Set the value stored in a spill slot.
  void setSpill(SpillLoc L, ValueIDNum ValueID) {
    LocIdx Idx = getOrTrackSpillLoc(L);
    LocIdxToIDNum[Idx] = ValueID;
  }

  /// Read whatever value is in a spill slot, or None if it isn't tracked.
  Optional<ValueIDNum> readSpill(SpillLoc L) {
    unsigned SpillID = SpillLocs.idFor(L);
    if (SpillID == 0)
      return None;

    unsigned LocID = getLocID(SpillID, true);
    LocIdx Idx = LocIDToLocIdx[LocID];
    return LocIdxToIDNum[Idx];
  }

  /// Determine the LocIdx of a spill slot. Return None if it previously
  /// hasn't had a value assigned.
  Optional<LocIdx> getSpillMLoc(SpillLoc L) {
    unsigned SpillID = SpillLocs.idFor(L);
    if (SpillID == 0)
      return None;
    unsigned LocNo = getLocID(SpillID, true);
    return LocIDToLocIdx[LocNo];
  }

  /// Return true if Idx is a spill machine location.
  bool isSpill(LocIdx Idx) const {
    return LocIdxToLocID[Idx] >= NumRegs;
  }

  MLocIterator begin() {
    return MLocIterator(LocIdxToIDNum, 0);
  }

  MLocIterator end() {
    return MLocIterator(LocIdxToIDNum, LocIdxToIDNum.size());
  }

  /// Return a range over all locations currently tracked.
  iterator_range<MLocIterator> locations() {
    return llvm::make_range(begin(), end());
  }

  std::string LocIdxToName(LocIdx Idx) const {
    unsigned ID = LocIdxToLocID[Idx];
    if (ID >= NumRegs)
      return Twine("slot ").concat(Twine(ID - NumRegs)).str();
    else
      return TRI.getRegAsmName(ID).str();
  }

  std::string IDAsString(const ValueIDNum &Num) const {
    std::string DefName = LocIdxToName(Num.getLoc());
    return Num.asString(DefName);
  }

  LLVM_DUMP_METHOD
  void dump() {
    for (auto Location : locations()) {
      std::string MLocName = LocIdxToName(Location.Value.getLoc());
      std::string DefName = Location.Value.asString(MLocName);
      dbgs() << LocIdxToName(Location.Idx) << " --> " << DefName << "\n";
    }
  }

  LLVM_DUMP_METHOD
  void dump_mloc_map() {
    for (auto Location : locations()) {
      std::string foo = LocIdxToName(Location.Idx);
      dbgs() << "Idx " << Location.Idx.asU64() << " " << foo << "\n";
    }
  }
};

} // end anonymous namespace

ValueIDNum ValueIDNum::EmptyValue = {UINT_MAX, UINT_MAX, UINT_MAX};

class MachineLocTracking {
private:
  /// Machine location/value transfer function, a mapping of which locations
  /// are assigned which new values.
  using MLocTransferMap = std::map<LocIdx, ValueIDNum>;

  const TargetRegisterInfo *TRI;
  const TargetInstrInfo *TII;
  const TargetFrameLowering *TFI;
  BitVector CalleeSavedRegs;

  /// Object to track machine locations as we step through a block. Could
  /// probably be a field rather than a pointer, as it's always used.
  MLocTracker *MTracker;

  /// Number of the current block LiveDebugValues is stepping through.
  unsigned CurBB;

  /// Number of the current instruction LiveDebugValues is evaluating.
  unsigned CurInst;

  // Mapping of blocks to and from their RPOT order.
  DenseMap<unsigned int, MachineBasicBlock *> OrderToBB;
  DenseMap<MachineBasicBlock *, unsigned int> BBToOrder;
  DenseMap<unsigned, unsigned> BBNumToRPO;

  /// Pair of MachineInstr, and its 1-based offset into the containing block.
  using InstAndNum = std::pair<const MachineInstr *, unsigned>;
  /// Map from debug instruction number to the MachineInstr labelled with that
  /// number, and its location within the function. Used to transform
  /// instruction numbers in DBG_INSTR_REFs into machine value numbers.
  std::map<uint64_t, InstAndNum> DebugInstrNumToInstr;

  /// Tests whether this instruction is a spill to a stack slot.
  bool isSpillInstruction(const MachineInstr &MI, MachineFunction *MF);

  /// Decide if @MI is a spill instruction and return true if it is. We use 2
  /// criteria to make this decision:
  /// - Is this instruction a store to a spill slot?
  /// - Is there a register operand that is both used and killed?
  /// TODO: Store optimization can fold spills into other stores (including
  /// other spills). We do not handle this yet (more than one memory operand).
  bool isLocationSpill(const MachineInstr &MI, MachineFunction *MF,
                       unsigned &Reg);

  /// If a given instruction is identified as a spill, return the spill slot
  /// and set \p Reg to the spilled register.
  Optional<SpillLoc> isRestoreInstruction(const MachineInstr &MI,
                                          MachineFunction *MF, unsigned &Reg);

  /// Given a spill instruction, extract the register and offset used to
  /// address the spill slot in a target independent way.
  SpillLoc extractSpillBaseRegAndOffset(const MachineInstr &MI);

  /// Observe a single instruction while stepping through a block.
  void process(MachineInstr &MI);

  /// Examines whether \p MI is copy instruction, and notifies trackers.
  /// \returns true if MI was recognized and processed.
  bool transferRegisterCopy(MachineInstr &MI);

  /// Examines whether \p MI is stack spill or restore  instruction, and
  /// notifies trackers. \returns true if MI was recognized and processed.
  bool transferSpillOrRestoreInst(MachineInstr &MI);

  /// Examines \p MI for any registers that it defines, and notifies trackers.
  void transferRegisterDef(MachineInstr &MI);

  /// Copy one location to the other, accounting for movement of subregisters
  /// too.
  void performCopy(Register Src, Register Dst);

  /// Step through the function, recording register definitions and movements
  /// in an MLocTracker. Convert the observations into a per-block transfer
  /// function in \p MLocTransfer, suitable for using with the machine value
  /// location dataflow problem.
  void
  produceMLocTransferFunction(MachineFunction &MF,
                              SmallVectorImpl<MLocTransferMap> &MLocTransfer,
                              unsigned MaxNumBlocks);

  /// Print the machine loc transfer function for each block.
  void
  printMLocTransferFunction(MachineFunction &MF,
                            SmallVectorImpl<MLocTransferMap> &MLocTransfer,
                            unsigned MaxNumBlocks);

  /// Solve the machine value location dataflow problem. Takes as input the
  /// transfer functions in \p MLocTransfer. Writes the output live-in and
  /// live-out arrays to the (initialized to zero) multidimensional arrays in
  /// \p MInLocs and \p MOutLocs. The outer dimension is indexed by block
  /// number, the inner by LocIdx.
  void mlocDataflow(ValueIDNum **MInLocs, ValueIDNum **MOutLocs,
                    SmallVectorImpl<MLocTransferMap> &MLocTransfer);

  /// Perform a control flow join (lattice value meet) of the values in machine
  /// locations at \p MBB. Follows the algorithm described in the file-comment,
  /// reading live-outs of predecessors from \p OutLocs, the current live ins
  /// from \p InLocs, and assigning the newly computed live ins back into
  /// \p InLocs. \returns two bools -- the first indicates whether a change
  /// was made, the second whether a lattice downgrade occurred. If the latter
  /// is true, revisiting this block is necessary.
  std::tuple<bool, bool>
  mlocJoin(MachineBasicBlock &MBB,
           SmallPtrSet<const MachineBasicBlock *, 16> &Visited,
           ValueIDNum **OutLocs, ValueIDNum *InLocs);
public:
  /// Boilerplate computation of some initial sets, artifical blocks and
  /// RPOT block ordering.
  void initialSetup(MachineFunction &MF);
  bool run(MachineFunction &MF);
  MachineLocTracking() = default;

  LLVM_DUMP_METHOD
  void dump_mloc_transfer(const MLocTransferMap &mloc_transfer) const;

  bool isCalleeSaved(LocIdx L) {
    unsigned Reg = MTracker->LocIdxToLocID[L];
    for (MCRegAliasIterator RAI(Reg, TRI, true); RAI.isValid(); ++RAI)
      if (CalleeSavedRegs.test(*RAI))
        return true;
    return false;
  }
};
