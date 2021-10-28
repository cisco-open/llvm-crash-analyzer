//===- Decompiler.h ----------------------------------------------*- C++ -*===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef CB_DECOMPILER_
#define CB_DECOMPILER_

#include "CoreFile/CoreFile.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/StringSaver.h"

#include "lldb/API/SBSymbolContextList.h"

#include <map>
#include <vector>
#include <unordered_map>
#include <unordered_set>

namespace llvm {

class DebugLoc;
class MachineBasicBlock;
class MachineFunction;
class MachineInstr;
class MCAsmInfo;
class MCContext;
class MCInstrAnalysis;
class MCInstrInfo;
class MCInstPrinter;
class MCRegisterInfo;
class MCSubtargetInfo;
class MCInst;
class Module;
class TargetLoweringObjectFile;
class TargetMachine;
class Triple;
class MachineModuleInfo;
struct SymbolInfoTy;
class formatted_raw_ostream;

namespace crash_blamer {

struct BlameFunction {
  StringRef Name;
  MachineFunction *MF;
};

using RegSet = SmallSet<Register, 32>;
using BlameModule = SmallVector<BlameFunction, 8>;

/// Used to decompile an object file to LLVM MIR representation.
class Decompiler {
  StringRef DefaultArch;
  std::unique_ptr<MCInstrInfo> MII;
  std::unique_ptr<TargetMachine> TM;

  std::unique_ptr<Module> Module;
  MachineModuleInfo *MMI;

  SmallVector<MachineFunction *, 8> BlameMFs;

  /// Private constructor, call Decompiler::Create(...).
  Decompiler();

  /// Set up the target.
  llvm::Error init(Triple TheTriple);

  SmallVector<long, 8> FunctionsThatAreNotInBT;

  lldb::SBTarget *target = nullptr;

  // Store debug info compile units for coresponding files.
  std::unordered_map<std::string, std::pair<DIFile *, DICompileUnit *>> CUs;

  // Store debug info for subprograms for coresponding functions.
  std::unordered_map<std::string, DISubprogram *> SPs;

  Triple mTriple;
  static LLVMContext Ctx;
  // Used to reconstruct the target from CALLs.
  // FIXME: Use `image lookup --address` in order to find
  // all the targets.
  std::unordered_map<uint64_t, StringRef> FuncStartSymbols;

  // Used to detect inlined functions that we missed to decompile
  // since they were not part of the backtrace.
  std::unordered_set<std::string> AlreadyDecompiledFns;

public:
  /// Create a Decompiler or get an appropriate error.
  ///
  /// \param TheTriple the triple to use when creating any required support
  /// classes needed to emit the DWARF.
  ///
  /// \returns a llvm::Expected that either contains a unique_ptr to a
  /// Decompiler
  /// or a llvm::Error.
  static llvm::Expected<std::unique_ptr<Decompiler>> create(Triple TheTriple);

  ~Decompiler();

  /// This will perform disassemble and transformation to LLVM MIR part.
  llvm::Error run(StringRef InputFile,
                  SmallVectorImpl<StringRef> &functionsFromCoreFile,
                  FrameToRegsMap &FrameToRegs,
                  SmallVectorImpl<BlameFunction> &BlameTrace,
                  std::map<llvm::StringRef, lldb::SBFrame> &FrameInfo,
                  lldb::SBTarget &target,
                  Triple TheTriple);

  /// Add Machine Function to the Module.
  MachineFunction &createMF(StringRef FunctionName);

  /// Add Machine Instr to the MF.
  MachineInstr *addInstr(
      MachineFunction *MF, MachineBasicBlock *MBB, MCInst &Inst, DebugLoc *Loc,
      bool IsCrashStart, RegSet &DefinedRegs,
      std::unordered_map<uint64_t, StringRef> &FuncStartSymbols,
      lldb::SBTarget &target);

  bool DecodeIntrsToMIR(
      Triple TheTriple, lldb::SBInstructionList &Instructions,
      lldb::SBAddress &FuncStart, lldb::SBAddress &FuncEnd,
      lldb::SBTarget &target, bool HaveDebugInfo, MachineFunction *MF,
      MachineBasicBlock *FirstMBB, StringRef OriginalFunction,
      DISubprogram *DISP, std::unordered_map<std::string, DISubprogram *> &SPs,
      LLVMContext &Ctx, lldb::addr_t CrashStartAddr,
      std::unordered_map<uint64_t, StringRef> &FuncStartSymbols,
      bool IsFnOutOfBt = false);

  SmallVector<MachineFunction *, 8> &getBlameMFs() { return BlameMFs; }

  void setTarget(lldb::SBTarget *t) { target = t; }
  lldb::SBTarget *getTarget() { return target; }

  MachineFunction* decompileOnDemand(StringRef TargetName);
  MachineFunction* decompileInlinedFnOutOfbt(StringRef TargetName,
      DIFile *File);
};

} // end crash_blamer namespace
} // end llvm namespace

#endif
