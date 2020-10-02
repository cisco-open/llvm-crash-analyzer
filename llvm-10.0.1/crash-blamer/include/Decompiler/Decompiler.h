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

#include <map>
#include <vector>

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
  std::unique_ptr<MCRegisterInfo> MRI;
  std::unique_ptr<MCAsmInfo> MAI;
  std::unique_ptr<MCContext> MC;
  std::unique_ptr<MCInstrAnalysis> MIA;
  std::unique_ptr<MCInstrInfo> MII;
  std::unique_ptr<MCSubtargetInfo> MSTI;
  std::unique_ptr<TargetMachine> TM;
  std::unique_ptr<MCDisassembler> DisAsm;
  std::unique_ptr<MCInstPrinter> InstPrinter;
  TargetLoweringObjectFile *TLOF; // Owned by TargetMachine;

  std::unique_ptr<Module> Module;
  MachineModuleInfo *MMI;

  SmallVector<MachineFunction *, 8> BlameMFs;

  /// Private constructor, call Decompiler::Create(...).
  Decompiler();

  /// Set up the target.
  llvm::Error init(Triple TheTriple);

public:
  /// This API is used to disassemble .text section of the object file.
  /// Most of these methods are taken from llvm-objdump tool.
  struct Disassembler {
    /// Creates symbol information.
    static SymbolInfoTy createSymbolInfo(const object::ObjectFile *Obj,
                                         const object::SymbolRef &Symbol);
    /// Creates dummy symbol information. It is being created if a section
    /// doesn't have any symbol at the start.
    static SymbolInfoTy createDummySymbolInfo(const object::ObjectFile *Obj,
                                              const uint64_t Addr,
                                              StringRef &Name, uint8_t Type);
    /// Used to skip zero bytes.
    static size_t countSkippableZeroBytes(ArrayRef<uint8_t> Buf);

    /// Print machine instruction. Used for testing purposes.
    static void printInst(MCInstPrinter &IP, const MCInst *MI,
                          ArrayRef<uint8_t> Bytes,
                          object::SectionedAddress Address,
                          formatted_raw_ostream &OS, StringRef Annot,
                          MCSubtargetInfo const &STI, StringRef ObjectFilename);

    /// Create dynamic elf symbols.
    static void addDynamicElfSymbols(
        const object::ObjectFile *Obj,
        std::map<object::SectionRef, SectionSymbolsTy> &AllSymbols);
    /// Create plt entries.
    static void
    addPltEntries(const object::ObjectFile *Obj,
                  std::map<object::SectionRef, SectionSymbolsTy> &AllSymbols,
                  StringSaver &Saver);
  };

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
                  SmallVectorImpl<BlameFunction> &BlameTrace);

  /// Add Machine Function to the Module.
  MachineFunction &createMF(StringRef FunctionName);

  /// Add Machine Instr to the MF.
  void addInstr(MachineFunction *MF, MachineBasicBlock *MBB,
                MCInst &Inst, DebugLoc *Loc, bool IsCrashStart,
                RegSet &DefinedRegs, StringRef TargetFnName);

  SmallVector<MachineFunction *, 8> &getBlameMFs() { return BlameMFs; }
};

} // end crash_blamer namespace
} // end llvm namespace

#endif
