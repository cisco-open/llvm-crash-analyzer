//===- Decompiler.cpp -----------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements crash blamer decompiler.
//
//===----------------------------------------------------------------------===//

#include "Decompiler/Decompiler.h"
#include "CoreFile/CoreFile.h"

#include "llvm/ADT/Triple.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/DebugInfo/DIContext.h"
#include "llvm/DebugInfo/Symbolize/Symbolize.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptionsCommandFlags.inc"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetLoweringObjectFile.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"

using namespace llvm;
using namespace llvm::object;

#define DEBUG_TYPE "crash-blamer-decompiler"

static cl::opt<bool> ShowDisassembly("show-disassemble", cl::Hidden,
                                     cl::init(false));

static cl::opt<std::string>
    ExportToMIR("export-to-mir",
                cl::desc("Export decompiled LLVM MIR into a file."),
                cl::value_desc("filename"), cl::init(""));

static StringSet<> DisasmSymbolSet;

crash_blamer::Decompiler::Decompiler() : TLOF(nullptr) {}
crash_blamer::Decompiler::~Decompiler() = default;

llvm::Expected<std::unique_ptr<crash_blamer::Decompiler>>
crash_blamer::Decompiler::create(Triple TheTriple) {
  std::unique_ptr<crash_blamer::Decompiler> Dec(new crash_blamer::Decompiler());
  llvm::Error error = Dec->init(TheTriple);
  if (error)
    return Expected<std::unique_ptr<crash_blamer::Decompiler>>(
        std::move(error));
  return Expected<std::unique_ptr<crash_blamer::Decompiler>>(std::move(Dec));
}

llvm::Error crash_blamer::Decompiler::init(Triple TheTriple) {
  std::string ErrorStr;
  std::string TripleName;

  // Get the target.
  const Target *TheTarget =
      TargetRegistry::lookupTarget(TripleName, TheTriple, ErrorStr);
  if (!TheTarget)
    return make_error<StringError>(ErrorStr, inconvertibleErrorCode());

  DefaultArch = TheTarget->getName();
  TripleName = TheTriple.getTriple();

  // Create all the MC Objects.
  MRI.reset(TheTarget->createMCRegInfo(TripleName));
  if (!MRI)
    return make_error<StringError>(Twine("no register info for target ") +
                                       TripleName,
                                   inconvertibleErrorCode());

  MCTargetOptions MCOptions = InitMCTargetOptionsFromFlags();
  MAI.reset(TheTarget->createMCAsmInfo(*MRI, TripleName, MCOptions));
  if (!MAI)
    return make_error<StringError>("no asm info for target " + TripleName,
                                   inconvertibleErrorCode());

  MSTI.reset(TheTarget->createMCSubtargetInfo(TripleName, "", ""));
  if (!MSTI)
    return make_error<StringError>("no subtarget info for target " + TripleName,
                                   inconvertibleErrorCode());

  MII.reset(TheTarget->createMCInstrInfo());
  if (!MII)
    return make_error<StringError>("no instr info info for target " +
                                       TripleName,
                                   inconvertibleErrorCode());

  TM.reset(TheTarget->createTargetMachine(TripleName, "", "", TargetOptions(),
                                          None));
  if (!TM)
    return make_error<StringError>("no target machine for target " + TripleName,
                                   inconvertibleErrorCode());

  TLOF = TM->getObjFileLowering();
  MC.reset(new MCContext(MAI.get(), MRI.get(), TLOF));
  TLOF->Initialize(*MC, *TM);

  DisAsm.reset(TheTarget->createMCDisassembler(*MSTI, *MC));
  if (!DisAsm)
    return make_error<StringError>("no disassembler for target " + TripleName,
                                   inconvertibleErrorCode());

  int AsmPrinterVariant = MAI->getAssemblerDialect();
  InstPrinter.reset(TheTarget->createMCInstPrinter(
      Triple(TripleName), AsmPrinterVariant, *MAI, *MII, *MRI));
  if (!InstPrinter)
    return make_error<StringError>("no mc instr printer for target " +
                                       TripleName,
                                   inconvertibleErrorCode());

  return Error::success();
}

static uint8_t getElfSymbolType(const ObjectFile *Obj, const SymbolRef &Sym) {
  assert(Obj->isELF());
  if (auto *Elf32LEObj = dyn_cast<ELF32LEObjectFile>(Obj))
    return Elf32LEObj->getSymbol(Sym.getRawDataRefImpl())->getType();
  if (auto *Elf64LEObj = dyn_cast<ELF64LEObjectFile>(Obj))
    return Elf64LEObj->getSymbol(Sym.getRawDataRefImpl())->getType();
  if (auto *Elf32BEObj = dyn_cast<ELF32BEObjectFile>(Obj))
    return Elf32BEObj->getSymbol(Sym.getRawDataRefImpl())->getType();
  if (auto *Elf64BEObj = cast<ELF64BEObjectFile>(Obj))
    return Elf64BEObj->getSymbol(Sym.getRawDataRefImpl())->getType();
  llvm_unreachable("Unsupported binary format");
}

// This is taken from llvm-objdump.
template <typename T, typename... Ts>
T unwrapOrError(Expected<T> EO, Ts &&... Args) {
  if (EO)
    return std::move(*EO);

  // FIXME: Make this better.
  outs().flush();
  WithColor::error(errs(), "crash-blamer") << "\n";
  exit(1);
}

void crash_blamer::Decompiler::Disassembler::addPltEntries(
    const ObjectFile *Obj, std::map<SectionRef, SectionSymbolsTy> &AllSymbols,
    StringSaver &Saver) {
  Optional<SectionRef> Plt = None;
  for (const SectionRef &Section : Obj->sections()) {
    Expected<StringRef> SecNameOrErr = Section.getName();
    if (!SecNameOrErr) {
      consumeError(SecNameOrErr.takeError());
      continue;
    }
    if (*SecNameOrErr == ".plt")
      Plt = Section;
  }
  if (!Plt)
    return;
  if (auto *ElfObj = dyn_cast<ELFObjectFileBase>(Obj)) {
    for (auto PltEntry : ElfObj->getPltAddresses()) {
      SymbolRef Symbol(PltEntry.first, ElfObj);
      uint8_t SymbolType = getElfSymbolType(Obj, Symbol);

      StringRef Name = unwrapOrError(Symbol.getName(), Obj->getFileName());
      if (!Name.empty())
        AllSymbols[*Plt].emplace_back(
            PltEntry.second, Saver.save((Name + "@plt").str()), SymbolType);
    }
  }
}

template <class ELFT>
static void
addDynamicElfSymbols(const ELFObjectFile<ELFT> *Obj,
                     std::map<SectionRef, SectionSymbolsTy> &AllSymbols) {
  for (auto Symbol : Obj->getDynamicSymbolIterators()) {
    uint8_t SymbolType = Symbol.getELFType();
    if (SymbolType == ELF::STT_SECTION)
      continue;

    uint64_t Address = unwrapOrError(Symbol.getAddress(), Obj->getFileName());
    // ELFSymbolRef::getAddress() returns size instead of value for common
    // symbols which is not desirable for disassembly output. Overriding.
    if (SymbolType == ELF::STT_COMMON)
      Address = Obj->getSymbol(Symbol.getRawDataRefImpl())->st_value;

    StringRef Name = unwrapOrError(Symbol.getName(), Obj->getFileName());
    if (Name.empty())
      continue;

    section_iterator SecI =
        unwrapOrError(Symbol.getSection(), Obj->getFileName());
    if (SecI == Obj->section_end())
      continue;

    AllSymbols[*SecI].emplace_back(Address, Name, SymbolType);
  }
}

void crash_blamer::Decompiler::Disassembler::addDynamicElfSymbols(
    const ObjectFile *Obj, std::map<SectionRef, SectionSymbolsTy> &AllSymbols) {
  assert(Obj->isELF());
  if (auto *Elf32LEObj = dyn_cast<ELF32LEObjectFile>(Obj))
    addDynamicElfSymbols(Elf32LEObj, AllSymbols);
  else if (auto *Elf64LEObj = dyn_cast<ELF64LEObjectFile>(Obj))
    addDynamicElfSymbols(Elf64LEObj, AllSymbols);
  else if (auto *Elf32BEObj = dyn_cast<ELF32BEObjectFile>(Obj))
    addDynamicElfSymbols(Elf32BEObj, AllSymbols);
  else if (auto *Elf64BEObj = cast<ELF64BEObjectFile>(Obj))
    addDynamicElfSymbols(Elf64BEObj, AllSymbols);
  else
    llvm_unreachable("Unsupported binary format");
}

static unsigned getInstStartColumn(const MCSubtargetInfo &STI) {
  return STI.getTargetTriple().isX86() ? 40 : 24;
}

void crash_blamer::Decompiler::Disassembler::printInst(
    MCInstPrinter &IP, const MCInst *MI, ArrayRef<uint8_t> Bytes,
    object::SectionedAddress Address, formatted_raw_ostream &OS,
    StringRef Annot, MCSubtargetInfo const &STI, StringRef ObjectFilename) {
  size_t Start = OS.tell();
  OS << format("%8" PRIx64 ":", Address.Address);

  OS << ' ';
  dumpBytes(Bytes, OS);

  // The output of printInst starts with a tab. Print some spaces so that
  // the tab has 1 column and advances to the target tab stop.
  unsigned TabStop = getInstStartColumn(STI);
  unsigned Column = OS.tell() - Start;
  OS.indent(Column < TabStop - 1 ? TabStop - 1 - Column : 7 - Column % 8);

  if (MI) {
    // See MCInstPrinter::printInst. On targets where a PC relative immediate
    // is relative to the next instruction and the length of a MCInst is
    // difficult to measure (x86), this is the address of the next
    // instruction.
    uint64_t Addr =
        Address.Address + (STI.getTargetTriple().isX86() ? Bytes.size() : 0);
    IP.printInst(MI, Addr, "", STI, OS);
  } else
    OS << "\t<unknown>";
}

size_t crash_blamer::Decompiler::Disassembler::countSkippableZeroBytes(
    ArrayRef<uint8_t> Buf) {
  // Find the number of leading zeroes.
  size_t N = 0;
  while (N < Buf.size() && !Buf[N])
    ++N;

  // We may want to skip blocks of zero bytes, but unless we see
  // at least 8 of them in a row.
  if (N < 8)
    return 0;

  // We skip zeroes in multiples of 4 because do not want to truncate an
  // instruction if it starts with a zero byte.
  return N & ~0x3;
}

SymbolInfoTy crash_blamer::Decompiler::Disassembler::createDummySymbolInfo(
    const ObjectFile *Obj, const uint64_t Addr, StringRef &Name, uint8_t Type) {
  return SymbolInfoTy(Addr, Name, Type);
}

SymbolInfoTy crash_blamer::Decompiler::Disassembler::createSymbolInfo(
    const ObjectFile *Obj, const SymbolRef &Symbol) {
  const StringRef FileName = Obj->getFileName();
  const uint64_t Addr = unwrapOrError(Symbol.getAddress(), FileName);
  const StringRef Name = unwrapOrError(Symbol.getName(), FileName);

  return SymbolInfoTy(Addr, Name,
                      Obj->isELF() ? getElfSymbolType(Obj, Symbol)
                                   : (uint8_t)ELF::STT_NOTYPE);
}

static std::unique_ptr<Module>
createModule(LLVMContext &Context, const DataLayout DL, StringRef InputFile) {
  auto Mod = std::make_unique<Module>(InputFile, Context);
  Mod->setDataLayout(DL);
  return Mod;
}

void crash_blamer::Decompiler::addInstr(MachineFunction *MF,
    MachineBasicBlock *MBB, MCInst &Inst, DebugLoc *Loc) {
  const unsigned Opcode = Inst.getOpcode();
  const MCInstrDesc &MCID = MII->get(Opcode);
  MachineInstrBuilder Builder = BuildMI(
      MBB, !Loc->getLine() ? DebugLoc() : *Loc, MCID);
  for (unsigned OpIndex = 0, E = Inst.getNumOperands(); OpIndex < E;
       ++OpIndex) {
    const MCOperand &Op = Inst.getOperand(OpIndex);
    if (Op.isReg()) {
      const bool IsDef = OpIndex < MCID.getNumDefs();
      unsigned Flags = 0;
      const MCOperandInfo &OpInfo = MCID.operands().begin()[OpIndex];
      if (IsDef && !OpInfo.isOptionalDef())
        Flags |= RegState::Define;
      Builder.addReg(Op.getReg(), Flags);
    } else if (Op.isImm()) {
      Builder.addImm(Op.getImm());
    } else if (!Op.isValid()) {
      llvm_unreachable("Operand is not set");
    } else {
      llvm_unreachable("Not yet implemented");
    }
  }
}

MachineFunction& crash_blamer::Decompiler::createMF(StringRef FunctionName) {
  // Create a dummy IR Function.
  auto &Context = Module->getContext();
  Function *F =
      Function::Create(FunctionType::get(Type::getVoidTy(Context), false),
                       Function::ExternalLinkage, FunctionName, *Module);
  BasicBlock *BB = BasicBlock::Create(Context, "entry", F);
  new UnreachableInst(Context, BB);

  // Making sure we can create a MachineFunction out of this Function even if it
  // contains no IR.
  F->setIsMaterializable(true);
  return MMI->getOrCreateMachineFunction(*F);
}

llvm::Error crash_blamer::Decompiler::run(
    StringRef InputFile, StringSet<> &functionsFromCoreFile) {
  llvm::outs() << "Decompiling...\n";
  std::string ErrorStr;
  auto ErrOrObj = object::ObjectFile::createObjectFile(InputFile);
  if (!ErrOrObj)
    return make_error<StringError>("unable to open " + InputFile,
                                   inconvertibleErrorCode());

  static LLVMContext Ctx;
  LLVMTargetMachine &LLVMTM = static_cast<LLVMTargetMachine &>(*TM.get());

  Module = createModule(Ctx, TM->createDataLayout(), InputFile);

  MMI = new MachineModuleInfo(&LLVMTM);
  if (!MMI)
    // FIXME: emit an error here.
    return Error::success();

  MMI->initialize();

  auto &Obj = *ErrOrObj->getBinary();

  // Mapping virtual address --> symbol name.
  std::map<SectionRef, SectionSymbolsTy> AllSymbols;
  SectionSymbolsTy AbsoluteSymbols;

  for (const SymbolRef &Symbol : Obj.symbols()) {
    StringRef Name = unwrapOrError(Symbol.getName(), InputFile);
    if (Name.empty())
      continue;

    if (Obj.isELF() && getElfSymbolType(&Obj, Symbol) == ELF::STT_SECTION)
      continue;

    section_iterator SecI = unwrapOrError(Symbol.getSection(), InputFile);
    if (SecI != Obj.section_end())
      AllSymbols[*SecI].push_back(Disassembler::createSymbolInfo(&Obj, Symbol));
    else
      AbsoluteSymbols.push_back(Disassembler::createSymbolInfo(&Obj, Symbol));
  }

  if (AllSymbols.empty() && Obj.isELF())
    Disassembler::addDynamicElfSymbols(&Obj, AllSymbols);

  BumpPtrAllocator A;
  StringSaver Saver(A);

  Disassembler::addPltEntries(&Obj, AllSymbols, Saver);

  // Create a mapping from virtual address to section.
  std::vector<std::pair<uint64_t, SectionRef>> SectionAddresses;
  for (SectionRef Sec : Obj.sections())
    SectionAddresses.emplace_back(Sec.getAddress(), Sec);
  llvm::stable_sort(SectionAddresses, [](const auto &LHS, const auto &RHS) {
    if (LHS.first != RHS.first)
      return LHS.first < RHS.first;
    return LHS.second.getSize() < RHS.second.getSize();
  });

  // Sort all the symbols, this allows us to use a simple binary search to find
  // Multiple symbols can have the same address. Use a stable sort to stabilize
  // the output.
  StringSet<> FoundDisasmSymbolSet;
  for (std::pair<const SectionRef, SectionSymbolsTy> &SecSyms : AllSymbols)
    stable_sort(SecSyms.second);
  stable_sort(AbsoluteSymbols);

  bool Is64Bits = Obj.getBytesInAddress() > 4;

  // Init the LLVM symbolizer used to get debug lines.
  symbolize::LLVMSymbolizer::Options SymbolizerOpts;
  std::unique_ptr<symbolize::LLVMSymbolizer> Symbolizer;
  SymbolizerOpts.PrintFunctions = DILineInfoSpecifier::FunctionNameKind::None;
  SymbolizerOpts.Demangle = false;
  SymbolizerOpts.DefaultArch = DefaultArch;
  Symbolizer.reset(new symbolize::LLVMSymbolizer(SymbolizerOpts));

  // Create Debug Info.
  DIBuilder DIB(*Module);
  DIFile *File = nullptr;
  DICompileUnit *CU = nullptr;

  for (const auto &Section : Obj.sections()) {
    if (!Section.isText() || Section.isVirtual())
      continue;

    StringRef SectionName = unwrapOrError(Section.getName(), Obj.getFileName());

    if (SectionName != ".text")
      continue;

    uint64_t SectionAddr = Section.getAddress();
    if (!File) {
      // Get file info.
      auto LineI =
          Symbolizer->symbolizeCode(Obj, {SectionAddr, Section.getIndex()});
      if (!LineI) {
        errs() << "Unable to find debug lines. Is it compiled with -g?\n";
        // TODO: return real error here.
        return Error::success();
      }
      File = DIB.createFile(LineI->FileName, "/");
      CU = DIB.createCompileUnit(dwarf::DW_LANG_C, File, "crash-blamer",
                                 /*isOptimized=*/true, "", 0);
    }

    uint64_t SectSize = Section.getSize();
    if (!SectSize)
      continue;

    // Get the list of all the symbols in this section.
    SectionSymbolsTy &Symbols = AllSymbols[Section];

    // TODO: Handle ARM, AARCH64 and MACH-O differences
    //       (e.g. ARM symbol mapping).

    // If the section has no symbol at the start, just insert a dummy one.
    if (Symbols.empty() || Symbols[0].Addr != 0) {
      Symbols.insert(Symbols.begin(),
                     Disassembler::createDummySymbolInfo(
                         &Obj, SectionAddr, SectionName,
                         Section.isText() ? ELF::STT_FUNC : ELF::STT_OBJECT));
    }

    SmallString<40> Comments;
    raw_svector_ostream CommentStream(Comments);

    ArrayRef<uint8_t> Bytes = arrayRefFromStringRef(
        unwrapOrError(Section.getContents(), Obj.getFileName()));

    uint64_t Size;
    uint64_t Index;
    bool PrintedSection = false;

    // Disassemble symbol by symbol.
    for (unsigned SI = 0, SE = Symbols.size(); SI != SE; ++SI) {
      std::string SymbolName = Symbols[SI].Name.str();

      uint64_t Start = Symbols[SI].Addr;
      if (Start < SectionAddr)
        continue;
      else
        FoundDisasmSymbolSet.insert(SymbolName);

      uint64_t End = SectionAddr + SectSize;
      if (SI + 1 < SE)
        End = std::min(End, Symbols[SI + 1].Addr);
      if (Start >= End)
        continue;
      Start -= SectionAddr;
      End -= SectionAddr;

      if (!PrintedSection) {
        PrintedSection = true;
        if (ShowDisassembly) {
          outs() << "\nDisassembly of section ";
          outs() << SectionName << ":\n";
        }
      }

      if (ShowDisassembly) {
        outs() << '\n';
        outs() << format(Is64Bits ? "%016" PRIx64 " " : "%08" PRIx64 " ",
                         SectionAddr + Start);
        outs() << '<' << SymbolName << ">:\n";
      }

      // Create MFs.
      MachineFunction *MF = nullptr;
      MachineBasicBlock *MBB = nullptr;
      DISubprogram *DISP = nullptr;

      if (functionsFromCoreFile.count(SymbolName)) {
        MF = &createMF(SymbolName);
        MBB = MF->CreateMachineBasicBlock();
        MF->push_back(MBB);
      }

      // Create DI subprogram.
      if (MF) {
        auto &F = MF->getFunction();
        auto SPType = DIB.createSubroutineType(DIB.getOrCreateTypeArray(None));
        DISubprogram::DISPFlags SPFlags =
            DISubprogram::SPFlagDefinition | DISubprogram::SPFlagOptimized;
        auto SP = DIB.createFunction(CU, F.getName(), F.getName(), File, 1,
                                     SPType, 1, DINode::FlagZero, SPFlags);
        DISP = SP;
        DIB.finalizeSubprogram(SP);
      }

      if (Section.isVirtual()) {
        if (ShowDisassembly)
          outs() << "...\n";
        continue;
      }

      DisAsm->onSymbolStart(SymbolName, Size,
                            Bytes.slice(Start, End - Start),
                            SectionAddr + Start, CommentStream);

      Start += Size;
      Index = Start;

      formatted_raw_ostream FOS(outs());

      while (Index < End) {
        uint64_t MaxOffset = End - Index;
        if (size_t N = Disassembler::countSkippableZeroBytes(
                Bytes.slice(Index, MaxOffset))) {
          if (ShowDisassembly)
            FOS << "\t\t..." << '\n';
          Index += N;
          continue;
        }

        // Disassemble a real instruction.
        MCInst Inst;
        bool Disassembled = DisAsm->getInstruction(
            Inst, Size, Bytes.slice(Index), SectionAddr + Index, CommentStream);
        if (Size == 0)
          Size = 1;

        if (Disassembled) {
          LLVM_DEBUG(Inst.dump());
          if (ShowDisassembly)
            Disassembler::printInst(*InstPrinter, &Inst,
                                    Bytes.slice(Index, Size),
                                    {SectionAddr + Index, Section.getIndex()},
                                    FOS, "", *MSTI, Obj.getFileName());

          DILineInfo DbgLineInfo = DILineInfo();
          auto LineInfo = Symbolizer->symbolizeCode(
              Obj, {SectionAddr + Index, Section.getIndex()});

          if (!LineInfo) {
            errs() << "Unable to find debug lines. Is it compiled with -g?\n";
            // TODO: return real error here.
            return Error::success();
          }
          DbgLineInfo = *LineInfo;

          // Fill the Machine Function.
          if (MF) {
            auto DILoc = DILocation::get(Ctx, DbgLineInfo.Line,
                                       DbgLineInfo.Column, DISP);
            DebugLoc Loc (DILoc);
            addInstr(MF, MBB, Inst, &Loc);
          }
        }

        if (ShowDisassembly)
          FOS << CommentStream.str();
        Comments.clear();

        if (ShowDisassembly)
          FOS << "\n";

        Index += Size;
      }
    }
  }

  MMI->finalize();

  if (ExportToMIR != "") {
    StringRef file_name = ExportToMIR;
    if (!file_name.endswith(".mir")) {
      errs() << "MIR file must be with '.mir' extension.\n";
      // TODO: return real error here.
      return Error::success();
    }

    std::error_code EC;
    raw_fd_ostream OS_FILE{ExportToMIR, EC, sys::fs::OF_Text};
    if (EC) {
      errs() << "Could not open file: " << EC.message() << ", " << ExportToMIR
             << '\n';
      return errorCodeToError(EC);
    }

    OS_FILE << "# crash-blamer decompiler\n";
    OS_FILE << "# Decompiled Module: " << InputFile << "\n\n";

    for (auto &F : *(Module.get())) {
      auto MF = MMI->getMachineFunction(F);
      if (MF)
        MF->print(OS_FILE);
    }
  }

  llvm::outs() << "Decompiled.\n";
  return Error::success();
}
