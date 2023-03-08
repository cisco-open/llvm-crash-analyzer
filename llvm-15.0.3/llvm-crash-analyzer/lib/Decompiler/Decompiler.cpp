//===- Decompiler.cpp -----------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements crash analyzer decompiler.
//
//===----------------------------------------------------------------------===//

#include "Decompiler/Decompiler.h"
#include "Decompiler/FixRegStateFlags.h"
#include "Target/CATargetInfo.h"

#include "llvm/ADT/Triple.h"
#include "llvm/CodeGen/MIRPrinter.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/DebugInfo/DIContext.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"

#include "Plugins/Disassembler/LLVMC/DisassemblerLLVMC.h"
#include "lldb/Core/Address.h"
#include "lldb/Core/Disassembler.h"
#include "lldb/Utility/ArchSpec.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/DataExtractor.h"

#include <sstream>
#include <unordered_set>

using namespace llvm;

#define DEBUG_TYPE "llvm-crash-analyzer-decompiler"

static cl::opt<bool> ShowDisassembly("show-disassemble", cl::Hidden,
                                     cl::init(false));

LLVMContext crash_analyzer::Decompiler::Ctx;

crash_analyzer::Decompiler::Decompiler() { DisassemblerLLVMC::Initialize(); }
crash_analyzer::Decompiler::~Decompiler() { DisassemblerLLVMC::Terminate(); }

llvm::Expected<std::unique_ptr<crash_analyzer::Decompiler>>
crash_analyzer::Decompiler::create(Triple TheTriple) {
  std::unique_ptr<crash_analyzer::Decompiler> Dec(
      new crash_analyzer::Decompiler());
  llvm::Error Err = Dec->init(TheTriple);
  if (Err)
    return Expected<std::unique_ptr<crash_analyzer::Decompiler>>(
        std::move(Err));
  return Expected<std::unique_ptr<crash_analyzer::Decompiler>>(std::move(Dec));
}

llvm::Error crash_analyzer::Decompiler::init(Triple TheTriple) {
  std::string ErrorStr;
  std::string TripleName;

  // Get the target.
  const Target *TheTarget =
      TargetRegistry::lookupTarget(TripleName, TheTriple, ErrorStr);
  if (!TheTarget)
    return make_error<StringError>(ErrorStr, inconvertibleErrorCode());

  DefaultArch = TheTarget->getName();
  TripleName = TheTriple.getTriple();

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

  return Error::success();
}

static std::unique_ptr<Module>
createModule(LLVMContext &Context, const DataLayout DL, StringRef InputFile) {
  auto Mod = std::make_unique<Module>(InputFile, Context);
  Mod->setDataLayout(DL);
  return Mod;
}

MachineInstr *crash_analyzer::Decompiler::addInstr(
    MachineFunction *MF, MachineBasicBlock *MBB, MCInst &Inst, DebugLoc *Loc,
    bool IsCrashStart, crash_analyzer::RegSet &DefinedRegs,
    std::unordered_map<uint64_t, StringRef> &FuncStartSymbols,
    lldb::SBTarget &Target) {
  const unsigned Opcode = Inst.getOpcode();
  const MCInstrDesc &MCID = MII->get(Opcode);
  MachineInstrBuilder Builder =
      BuildMI(MBB, !Loc->getLine() ? DebugLoc() : *Loc, MCID);

  auto TII = MF->getSubtarget().getInstrInfo();
  auto TRI = MF->getSubtarget().getRegisterInfo();

  bool CSRGenerated = false;

  for (unsigned OpIndex = 0, E = Inst.getNumOperands(); OpIndex < E;
       ++OpIndex) {
    const MCOperand &Op = Inst.getOperand(OpIndex);
    if (Op.isReg()) {
      const bool IsDef = OpIndex < MCID.getNumDefs();
      unsigned Flags = 0;
      const MCOperandInfo &OpInfo = MCID.operands().begin()[OpIndex];
      if (IsDef && !OpInfo.isOptionalDef()) {
        Flags |= RegState::Define;
        DefinedRegs.insert(Op.getReg());
      }
      Builder.addReg(Op.getReg(), Flags);
    } else if (Op.isImm()) {
      Builder.addImm(Op.getImm());
    } else if (Op.isExpr()) {
      auto Expr = Op.getExpr();
      if (auto ConstExpr = dyn_cast<MCConstantExpr>(Expr)) {
        if (!MCID.isCall()) {
          Builder.addImm(ConstExpr->getValue());
          continue;
        }

        StringRef TargetFnName = "";
        // If it is a call and there is no target symbol.
        if (!FuncStartSymbols.count(ConstExpr->getValue())) {
          // Remember this target to process it later.
          FunctionsThatAreNotInBT.push_back(ConstExpr->getValue());
          lldb::SBAddress addr(ConstExpr->getValue(), Target);
          auto SymCtx = Target.ResolveSymbolContextForAddress(
              addr, lldb::eSymbolContextEverything);
          if (SymCtx.IsValid() && SymCtx.GetSymbol().IsValid())
            TargetFnName = SymCtx.GetSymbol().GetDisplayName();
          else {
            Builder.addImm(ConstExpr->getValue());
            continue;
          }
        }
        auto &Context = MF->getFunction().getContext();
        if (TargetFnName == "")
          TargetFnName = FuncStartSymbols[ConstExpr->getValue()];
        FunctionCallee Callee = Module->getOrInsertFunction(
            TargetFnName, FunctionType::get(Type::getVoidTy(Context), false));
        GlobalValue *GV = dyn_cast<GlobalValue>(Callee.getCallee());
        if (!GV) {
          Builder.addImm(ConstExpr->getValue());
          continue;
        }
        Builder.addGlobalAddress(GV);
        // Make sure we generate the csr only once.
        if (!CSRGenerated) {
          // TODO: Add the callee saved reg mask for indirect calls.
          Builder.addRegMask(TRI->getCallPreservedMask(
              *MF, MF->getFunction().getCallingConv()));
          CSRGenerated = true;
        }
        continue;
      }
      llvm_unreachable("Not yet implemented expr");
    } else if (!Op.isValid()) {
      llvm_unreachable("Operand is not set");
    } else {
      llvm_unreachable("Not yet implemented");
    }
  }

  // If it is an XOR eax, eax mark them as undef. It's a simple
  // way of setting a reg to zero.
  if (TII->isXORSimplifiedSetToZero(*Builder)) {
    Builder->getOperand(1).setIsUndef();
    Builder->getOperand(2).setIsUndef();
  }

  if (IsCrashStart)
    Builder->setFlag(MachineInstr::CrashStart);

  return &*Builder;
}

MachineInstr *crash_analyzer::Decompiler::addNoop(MachineFunction *MF,
                                                  MachineBasicBlock *MBB,
                                                  DebugLoc *Loc) {
  auto TII = MF->getSubtarget().getInstrInfo();
  llvm::MCInst Inst;
  Inst = TII->getNop();
  if (const unsigned NoopOpcode = Inst.getOpcode()) {
    const MCInstrDesc &MCID = MII->get(NoopOpcode);
    MachineInstrBuilder Builder = BuildMI(MBB, DebugLoc(), MCID);
    return &*Builder;
  }
  return nullptr;
}

MachineFunction &crash_analyzer::Decompiler::createMF(StringRef FunctionName) {
  // Create a dummy IR Function.
  auto &Context = Module->getContext();

  // If we already created IR declaration for this, we don't need it anymore
  // since we are creating the definition here.
  auto *FDecl = Module->getFunction(FunctionName);
  if (FDecl)
    FDecl->removeFromParent();

  Function *F =
      Function::Create(FunctionType::get(Type::getVoidTy(Context), false),
                       Function::ExternalLinkage, FunctionName, *Module);
  BasicBlock *BB = BasicBlock::Create(Context, "entry", F);
  new UnreachableInst(Context, BB);

  // Making sure we can create a MachineFunction out of this Function even if it
  // contains no IR.
  F->setIsMaterializable(true);
  MachineFunction *MF = &MMI->getOrCreateMachineFunction(*F);
  AlreadyDecompiledFns.insert({FunctionName.str(), MF});
  return *MF;
}

bool crash_analyzer::Decompiler::DecodeIntrsToMIR(
    Triple TheTriple, lldb::SBInstructionList &Instructions,
    lldb::SBAddress &FuncStart, lldb::SBAddress &FuncEnd,
    lldb::SBTarget &Target, bool HaveDebugInfo, MachineFunction *MF,
    MachineBasicBlock *FirstMBB, StringRef OriginalFunction, DISubprogram *DISP,
    std::unordered_map<std::string, DISubprogram *> &SPs, LLVMContext &Ctx,
    lldb::addr_t CrashStartAddr,
    std::unordered_map<uint64_t, StringRef> &FuncStartSymbols,
    bool IsFnOutOfBt) {
  llvm::outs() << "Decompiling " << OriginalFunction << "\n";

  MachineBasicBlock *MBB = FirstMBB;
  bool PrevBranch = true;
  crash_analyzer::RegSet DefinedRegs;

  lldb_private::ArchSpec Arch(TheTriple.normalize());
  lldb::DisassemblerSP Disassembler_sp =
      lldb_private::Disassembler::FindPlugin(Arch, nullptr, nullptr);

  // Jumps to be updated with proper targets ( in form of bb).
  // This maps the target address with the jump.
  std::unordered_multimap<uint64_t, MachineInstr *> BranchesToUpdate;

  std::pair<lldb::addr_t, lldb::addr_t> FuncRange{FuncStart.GetFileAddress(),
                                                  FuncEnd.GetFileAddress()};
  lldb::addr_t FuncLoadAddr = FuncStart.GetLoadAddress(Target);

  lldb::WritableDataBufferSP BufferSp(
      new lldb_private::DataBufferHeap(FuncRange.second, 0));
  lldb::SBError Err;
  Target.ReadMemory(FuncStart, BufferSp->GetBytes(), BufferSp->GetByteSize(),
                    Err);

  lldb_private::DataExtractor Extractor(BufferSp, Target.GetByteOrder(),
                                        Target.GetAddressByteSize());
  Disassembler_sp->DecodeInstructions(FuncLoadAddr, Extractor, 0,
                                      Instructions.GetSize(), false, false);

  auto CATI = getCATargetInfoInstance();
  bool CrashStartSet = false;
  lldb_private::InstructionList &InstructionList =
      Disassembler_sp->GetInstructionList();
  size_t numInstr = InstructionList.GetSize();
  for (size_t k = 0; k < numInstr; ++k) {
    // This is used for tracking inlined functions.
    // The instrs from such fn will be stored in a .text of another fn.
    auto InstSP = InstructionList.GetInstructionAtIndex(k);
    uint64_t InstAddr = InstSP->GetAddress().GetFileAddress();

    StringRef InlinedFnName = "";

    uint32_t Line = 0;
    uint32_t Column = 0;
    if (HaveDebugInfo) {
      auto SBInst = Instructions.GetInstructionAtIndex(k);
      Line = SBInst.GetAddress().GetLineEntry().GetLine();
      Column = SBInst.GetAddress().GetLineEntry().GetColumn();
      if (SBInst.GetAddress().GetBlock().IsInlined()) {
        InlinedFnName = SBInst.GetAddress().GetBlock().GetInlinedName();
        if (!AlreadyDecompiledFns.count(InlinedFnName.str())) {
          auto InlineFnOutOfBt =
              decompileInlinedFnOutOfbt(InlinedFnName, DISP->getFile());
          (void)InlineFnOutOfBt;
        }
      }
    }

    llvm::MCInst Inst;
    auto InstSize = InstSP->GetMCInst(Inst);
    if (InstSize == 0)
      return false;

    const unsigned Opcode = Inst.getOpcode();
    const MCInstrDesc &MCID = MII->get(Opcode);
    object::SectionedAddress Addr = {InstAddr,
                                     object::SectionedAddress::UndefSection};

    MachineInstr *MI = nullptr;

    // Fill the Machine Function.
    if (MF) {
      // If it is not a branch and we previously did not decompile a
      // branch,
      // check if this should start a new basic block. For example
      // default:
      // label within a switch usually has this structure.
      if (!MCID.isBranch() && BranchesToUpdate.count(Addr.Address) &&
          !PrevBranch) {
        MachineBasicBlock *OldBB = MBB;
        MBB = MF->CreateMachineBasicBlock();
        if (!OldBB->isSuccessor(MBB))
          OldBB->addSuccessor(MBB);
        MF->push_back(MBB);
      }

      // This is used to prevent wrong DI SP attached to inlined
      // instructions.
      if (!InlinedFnName.empty()) {
        if (SPs.count(InlinedFnName.str()))
          DISP = SPs[InlinedFnName.str()];
      } else {
        if (SPs.count(OriginalFunction.str()))
          DISP = SPs[OriginalFunction.str()];
      }

      auto DILoc = DILocation::get(Ctx, Line, Column, DISP);
      DebugLoc Loc = DebugLoc(DILoc);
      // For the functions out of backtrace we should analize whole
      // function, so crash-start flag should go at the end of the fn.
      if (IsFnOutOfBt && k == (numInstr - 1))
        MI = addInstr(MF, MBB, Inst, &Loc, true, DefinedRegs, FuncStartSymbols,
                      Target);
      else
        MI = addInstr(MF, MBB, Inst, &Loc, CrashStartAddr == Addr.Address,
                      DefinedRegs, FuncStartSymbols, Target);

      assert(MI && "Failed to add the instruction ...");

      // We maintain mapping between MI and its PC address, since TII for
      // x86 doesn't support MI size getter. For x86, instructions with the
      // same Opcode could have different sizes.
      // TODO: Add support in X86InstrInfo to make this more efficient.
      if (!CrashStartSet)
        CATI->setInstAddr(MI, Addr.Address, InstSize);

      if (MI->getFlag(MachineInstr::CrashStart))
        CrashStartSet = true;
      // There could be multiple branches targeting the same
      // MBB.
      while (BranchesToUpdate.count(Addr.Address)) {
        auto BranchIt = BranchesToUpdate.find(Addr.Address);
        MachineInstr *BranchInstr = BranchIt->second;
        // In the first shot it was an imm representing the address.
        // Now we set the real MBB as an operand.
        // FIXME: Should call RemoveOperand(0) and then set it to
        // the MBB.
        BranchInstr->getOperand(0) = MachineOperand::CreateMBB(MBB);
        if (!BranchInstr->getParent()->isSuccessor(MBB))
          BranchInstr->getParent()->addSuccessor(MBB);
        BranchesToUpdate.erase(BranchIt);
      }

      // If the last decompiled instruction is a Call, check if it is the
      // crash-start for this function.
      if (k + 1 == numInstr && !CrashStartSet && MI->isCall()) {
        auto NoopInst = addNoop(MF, MBB, &Loc);
        if (NoopInst && CrashStartAddr == Addr.Address + InstSize) {
          NoopInst->setFlag(MachineInstr::CrashStart);
          CrashStartSet = true;
        }
      }
    }

    // If this is a branch, start new MBB.
    if (MF && MI && MCID.isBranch()) {
      MachineBasicBlock *OldBB = MBB;
      MBB = MF->CreateMachineBasicBlock();
      if (MI && MI->isConditionalBranch() && !OldBB->isSuccessor(MBB))
        OldBB->addSuccessor(MBB);
      MF->push_back(MBB);
      // Rememer the target address, so we can fix it
      // with the proper BB in the case of regular jump.
      // It can be a jump instruction where the target is
      // in a register:
      //    JMP64r $r10
      if (MI->getOperand(0).isImm()) {
        uint64_t TargetBBAddr = MI->getOperand(0).getImm();
        BranchesToUpdate.insert({TargetBBAddr, MI});
      }
      PrevBranch = true;
    } else
      PrevBranch = false;
    InlinedFnName = "";
  }

  assert(CrashStartSet &&
         "Decompiled function should contain crash-start instruction");
  return true;
}

llvm::Error crash_analyzer::Decompiler::run(
    StringRef InputFile, SmallVectorImpl<StringRef> &FunctionsFromCoreFile,
    FrameToRegsMap &FrameToRegs, SmallVectorImpl<BlameFunction> &BlameTrace,
    std::map<llvm::StringRef, lldb::SBFrame> &FrameInfo, lldb::SBTarget &Target,
    Triple TheTriple) {
  llvm::outs() << "Decompiling...\n";

  LLVMTargetMachine &LLVMTM = static_cast<LLVMTargetMachine &>(*TM.get());

  Module = createModule(Ctx, TM->createDataLayout(), InputFile);

  DecTriple = TheTriple;

  MMI = new MachineModuleInfo(&LLVMTM);
  if (!MMI)
    return make_error<StringError>("MachineModuleInfo construction failed",
                                   inconvertibleErrorCode());
  MMI->initialize();

  // Map of the functions we are about to decompile.
  std::unordered_set<std::string> FunctionsToDecompile;
  for (StringRef f : FunctionsFromCoreFile)
    FunctionsToDecompile.insert(f.str());

  // Create Debug Info.
  DIBuilder DIB(*Module);

  for (auto &Frame : FrameInfo) {
    auto FuncAddr =
        Frame.second.GetFunction().GetStartAddress().GetFileAddress();
    FuncStartSymbols[FuncAddr] = Frame.first;
  }

  // BlameTrace has the same order of functions as FunctionsFromCoreFile.
  for (auto &BF : BlameTrace) {
    auto Frame = FrameInfo.find(BF.Name);
    if (Frame == FrameInfo.end())
      continue;
    // Skip artificial frames.
    if (Frame->second.IsArtificial())
      continue;

    lldb::SBInstructionList Instructions;
    lldb::SBAddress FuncStart, FuncEnd;
    bool HaveDebugInfo = false;

    auto Func = Frame->second.GetFunction();
    if (!Func) {
      WithColor::warning()
          << "No debugging info found for a function from backtrace. "
          << "Please provide debugging info for the exe and all libraries.\n";
      auto Symbol = Frame->second.GetSymbol();
      if (!Symbol) {
        WithColor::warning()
            << "No symbols found for a function "
            << "from backtrace. Please "
            << "provide symbols for the exe and all libraries.\n";
        continue;
      }
      Instructions = Symbol.GetInstructions(Target);
      FuncStart = Symbol.GetStartAddress();
      FuncEnd = Symbol.GetEndAddress();
    } else {
      HaveDebugInfo = true;
      Instructions = Func.GetInstructions(Target);
      FuncStart = Func.GetStartAddress();
      FuncEnd = Func.GetEndAddress();
    }

    std::string FileDirInfo, FileNameInfo, AbsFileName;
    if (HaveDebugInfo) {
      FileDirInfo = Frame->second.GetCompileUnit().GetFileSpec().GetDirectory();
      FileNameInfo = Frame->second.GetCompileUnit().GetFileSpec().GetFilename();
      AbsFileName =
          (Twine(FileDirInfo) + Twine("/") + Twine(FileNameInfo)).str();
    }

    if (ShowDisassembly) {
      outs() << "\nDissasemble of the functions from backtrace:\n";
      outs() << Frame->second.Disassemble();
    }

    // Create MFs.
    MachineFunction *MF = nullptr;
    MachineBasicBlock *MBB = nullptr;
    DISubprogram *DISP = nullptr;
    std::string InstrAddr;
    uint64_t AddrValue = 0;

    StringRef FunctionName = Frame->first;
    MF = &createMF(FunctionName);
    MBB = MF->CreateMachineBasicBlock();
    MF->push_back(MBB);

    DIFile *File = nullptr;
    DICompileUnit *CU = nullptr;

    if (MF && HaveDebugInfo)
      handleCompileUnitDI(DIB, AbsFileName, &File, &CU);

    // Once we created the DI file, create DI subprogram.
    if (HaveDebugInfo && !DISP && File && CU && MF)
      handleSubprogramDI(DIB, MF, CU, &DISP, File);

    // Here we stop decompiling inlined functions. This MF is dummy fn,
    // since the instructions of will be in the MF where it got inlined. We need
    // this MF in order to attach DISubprogram on it.
    // TODO: We assume that inlined functions is in the same compilation unit as
    // the function where it got inlined, but there is Cross-CU inlining by
    // using LTO, but it will be handled as future work.
    if (Frame->second.IsInlined()) {
      auto TII = MF->getSubtarget().getInstrInfo();
      MCInst NopInst;
      NopInst = TII->getNop();
      const unsigned Opcode = NopInst.getOpcode();
      const MCInstrDesc &MCID = MII->get(Opcode);
      BuildMI(MBB, DebugLoc(), MCID);

      // Map the fn from backtrace to the MF.
      // Crash order starts from 1.
      MF->setCrashOrder(Frame->second.GetFrameID() + 1);
      BF.MF = MF;

      continue;
    }

    // Get the address of the latest instruction executed within a frame.
    auto Regs = FrameToRegs.find(FunctionName);
    auto CATI = getCATargetInfoInstance();
    // Get the value of $rip register, since it holds the address of current
    // instr being executed.
    for (auto &Reg : Regs->second) {
      if (CATI->isPCRegister(Reg.regName)) {
        InstrAddr = Reg.regValue;
        std::istringstream converter(InstrAddr);
        converter >> std::hex >> AddrValue;
        break;
      }
    }

    // Fill up the register-memory state into coresponding MF attributes.
    MachineFunction::RegisterCrashInfo RegInfo;
    for (auto &Reg : Regs->second)
      RegInfo.push_back({Reg.regName, Reg.regValue});
    MF->addCrashRegInfo(RegInfo);

    if (!DecodeIntrsToMIR(TheTriple, Instructions, FuncStart, FuncEnd, Target,
                          HaveDebugInfo, MF, MBB, Frame->first, DISP, SPs, Ctx,
                          AddrValue, FuncStartSymbols))
      return make_error<StringError>("unable to decompile an instruction",
                                     inconvertibleErrorCode());

    LLVM_DEBUG(if (MF) {
      dbgs() << "Decompiled MF:\n";
      MF->dump();
    });

    // Map the fn from backtrace to the MF.
    // Crash order starts from 1.
    MF->setCrashOrder(Frame->second.GetFrameID() + 1);
    BF.MF = MF;

    // Remove the function from working set.
    FunctionsToDecompile.erase(FunctionName.str());
    // If we decompiled all the functions, break the loop.
    if (FunctionsToDecompile.empty())
      break;
  }

  // Create MFs for function out of backtrace. This is now handled in the
  // decompileOnDemand() which is being called during Taint Analysis.

  // Run FixRegStateFlags pass for each basic block.
  FixRegStateFlags FRSF;
  for (auto &BF : BlameTrace) {
    if (BF.MF)
      FRSF.run(*(BF.MF));
  }

  MMI->finalize();

  // Rememer the MFs for analysis.
  for (auto &F : *(Module.get())) {
    auto MF = MMI->getMachineFunction(F);
    if (MF)
      BlameMFs.push_back(MF);
  }

  llvm::outs() << "Decompiled.\n";
  return Error::success();
}

MachineFunction *
crash_analyzer::Decompiler::decompileInlinedFnOutOfbt(StringRef TargetName,
                                                      DIFile *File) {
  if (!File)
    return nullptr;
  if (TargetName == "")
    return nullptr;
  if (!CUs.count(File->getFilename().str()))
    return nullptr;

  auto MF = &createMF(TargetName);
  auto MBB = MF->CreateMachineBasicBlock();
  MF->push_back(MBB);

  DICompileUnit *CU = CUs[File->getFilename().str()].second;

  // Create Debug Info.
  DIBuilder DIB(*Module);
  DISubprogram *SP = nullptr;
  handleSubprogramDI(DIB, MF, CU, &SP, File);

  auto TII = MF->getSubtarget().getInstrInfo();
  MCInst NopInst;
  NopInst = TII->getNop();
  const unsigned Opcode = NopInst.getOpcode();
  const MCInstrDesc &MCID = MII->get(Opcode);
  BuildMI(MBB, DebugLoc(), MCID);
  MF->setCrashOrder(0);
  AlreadyDecompiledFns.insert({TargetName.str(), MF});
  return MF;
}

void crash_analyzer::Decompiler::handleSubprogramDI(DIBuilder &DIB,
                                                    MachineFunction *MF,
                                                    DICompileUnit *CU,
                                                    DISubprogram **SPAdr,
                                                    DIFile *File) {
  auto &F = MF->getFunction();
  auto SPType = DIB.createSubroutineType(DIB.getOrCreateTypeArray(None));
  DISubprogram::DISPFlags SPFlags =
      DISubprogram::SPFlagDefinition | DISubprogram::SPFlagOptimized;
  auto SP = DIB.createFunction(CU, F.getName(), F.getName(), File, 1, SPType, 1,
                               DINode::FlagZero, SPFlags);
  (const_cast<Function *>(&F))->setSubprogram(SP);
  DIB.finalizeSubprogram(SP);
  if (!SPs.count(MF->getName().str()))
    SPs.insert({MF->getName().str(), SP});
  *SPAdr = SP;
}

void crash_analyzer::Decompiler::handleCompileUnitDI(DIBuilder &DIB,
                                                     std::string AbsFileName,
                                                     DIFile **FileAdr,
                                                     DICompileUnit **CUAdr) {
  if (!CUs.count(AbsFileName)) {
    *FileAdr = DIB.createFile(AbsFileName, "/");
    *CUAdr = DIB.createCompileUnit(
        dwarf::DW_LANG_C, *FileAdr, "llvm-crash-analyzer", /*isOptimized=*/true,
        "", 0, StringRef(), DICompileUnit::DebugEmissionKind::FullDebug, 0,
        true, false, DICompileUnit::DebugNameTableKind::Default, false, "", "",
        true);
    CUs.insert({AbsFileName, std::make_pair(*FileAdr, *CUAdr)});
  } else {
    *FileAdr = CUs[AbsFileName].first;
    *CUAdr = CUs[AbsFileName].second;
  }
}

bool crash_analyzer::Decompiler::handleDebugInfo(lldb::SBAddress FuncStart,
                                                 MachineFunction *MF,
                                                 DISubprogram **SPAdr) {
  // Create Debug Info.
  DIBuilder DIB(*Module);

  // Handle debug info if this comes from another module.
  if (!FuncStart.GetFunction())
    return false;

  DIFile *File = nullptr;
  DICompileUnit *CU = nullptr;
  std::string FileDirInfo, FileNameInfo, AbsFileName;
  FileDirInfo = FuncStart.GetCompileUnit().GetFileSpec().GetDirectory();
  FileNameInfo = FuncStart.GetCompileUnit().GetFileSpec().GetFilename();
  AbsFileName = (Twine(FileDirInfo) + Twine("/") + Twine(FileNameInfo)).str();

  handleCompileUnitDI(DIB, AbsFileName, &File, &CU);

  handleSubprogramDI(DIB, MF, CU, SPAdr, File);

  return true;
}

bool crash_analyzer::Decompiler::decompileInstrs(Triple TheTriple,
                                                 lldb::SBSymbolContext &SymCtx,
                                                 lldb::SBTarget &Target,
                                                 MachineFunction *MF) {
  lldb::SBInstructionList Instructions;
  lldb::SBAddress FuncStart, FuncEnd;
  auto Symbol = SymCtx.GetSymbol();
  Instructions = Symbol.GetInstructions(Target);
  FuncStart = Symbol.GetStartAddress();
  FuncEnd = Symbol.GetEndAddress();

  bool HasDbgInfo = false;
  auto Fn = FuncStart.GetFunction();
  MachineBasicBlock *MBB = MF->CreateMachineBasicBlock();
  MF->push_back(MBB);

  DISubprogram *SP = nullptr;

  HasDbgInfo = handleDebugInfo(FuncStart, MF, &SP);

  if (!DecodeIntrsToMIR(TheTriple, Instructions, FuncStart, FuncEnd, Target,
                        HasDbgInfo, MF, MBB,
                        SymCtx.GetSymbol().GetDisplayName(), SP, SPs, Ctx, 0,
                        FuncStartSymbols, true /*IsFnOutOfBt*/))
    return false;

  return true;
}

MachineFunction *
crash_analyzer::Decompiler::decompileOnDemand(StringRef TargetName) {
  if (TargetName == "")
    return nullptr;

  if (!DecTarget)
    return nullptr;

  if (AlreadyDecompiledFns.count(TargetName.str()))
    return AlreadyDecompiledFns[TargetName.str()];

  auto SymCtxs = DecTarget->FindFunctions(TargetName.data());
  if (SymCtxs.GetSize() != 1) {
    LLVM_DEBUG(llvm::dbgs()
               << "Multiple symbols found for: " << TargetName << '\n');
    return nullptr;
  }

  auto SymCtx = SymCtxs.GetContextAtIndex(0);
  if (!(SymCtx.IsValid() && SymCtx.GetSymbol().IsValid())) {
    LLVM_DEBUG(llvm::dbgs() << "Symbols isn't valid: " << TargetName << '\n');
    return nullptr;
  }

  MachineFunction *MF = &createMF(SymCtx.GetSymbol().GetDisplayName());
  if (!decompileInstrs(DecTriple, SymCtx, *DecTarget, MF))
    return nullptr;

  // Functions that are out of backtrace have 0 crash order.
  MF->setCrashOrder(0);

  return MF;
}
