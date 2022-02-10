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
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"

#include "lldb/Core/Address.h"
#include "lldb/Core/Disassembler.h"
#include "lldb/Utility/ArchSpec.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/DataExtractor.h"
#include "Plugins/Disassembler/llvm/DisassemblerLLVMC.h"

#include <sstream>
#include <unordered_set>

using namespace llvm;

#define DEBUG_TYPE "llvm-crash-analyzer-decompiler"

static cl::opt<bool> ShowDisassembly("show-disassemble", cl::Hidden,
                                     cl::init(false));

static cl::opt<std::string> PrintDecMIR("print-decompiled-mir",
                                        cl::desc("Print decompiled LLVM MIR."),
                                        cl::value_desc("filename"),
                                        cl::init(""));

// TODO: Remove this. This option isn't needed anymore, since we decompileOnDemand
// during TA when needed to avoid poor performance in big projects when we have
// big number of calls.
static cl::opt<bool> DecompileFnsOutOfbt("decompile-fns-out-of-bt", cl::Hidden,
                                         cl::init(false));

LLVMContext crash_analyzer::Decompiler::Ctx;

crash_analyzer::Decompiler::Decompiler() {
  DisassemblerLLVMC::Initialize();
}
crash_analyzer::Decompiler::~Decompiler() { DisassemblerLLVMC::Terminate(); }

llvm::Expected<std::unique_ptr<crash_analyzer::Decompiler>>
crash_analyzer::Decompiler::create(Triple TheTriple) {
  std::unique_ptr<crash_analyzer::Decompiler> Dec(new crash_analyzer::Decompiler());
  llvm::Error error = Dec->init(TheTriple);
  if (error)
    return Expected<std::unique_ptr<crash_analyzer::Decompiler>>(
        std::move(error));
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
    return make_error<StringError>(
        "no instr info info for target " + TripleName,
        inconvertibleErrorCode());

  TM.reset(TheTarget->createTargetMachine(TripleName, "", "", TargetOptions(),
                                          None));
  if (!TM)
    return make_error<StringError>("no target machine for target " + TripleName,
                                   inconvertibleErrorCode());

  return Error::success();
}

static std::unique_ptr<Module> createModule(LLVMContext &Context,
                                            const DataLayout DL,
                                            StringRef InputFile) {
  auto Mod = std::make_unique<Module>(InputFile, Context);
  Mod->setDataLayout(DL);
  return Mod;
}

MachineInstr *crash_analyzer::Decompiler::addInstr(
    MachineFunction *MF, MachineBasicBlock *MBB, MCInst &Inst, DebugLoc *Loc,
    bool IsCrashStart, crash_analyzer::RegSet &DefinedRegs,
    std::unordered_map<uint64_t, StringRef> &FuncStartSymbols,
    lldb::SBTarget &target) {
  const unsigned Opcode = Inst.getOpcode();
  const MCInstrDesc &MCID = MII->get(Opcode);
  MachineInstrBuilder Builder =
      BuildMI(MBB, !Loc->getLine() ? DebugLoc() : *Loc, MCID);

  auto TII = MF->getSubtarget().getInstrInfo();
  auto TRI = MF->getSubtarget().getRegisterInfo();
  // No need for the NOOPs within MIR representation.
  // TODO: Optimize this. Can we check if it is a noop from MCID?
  if (TII->isNoopInstr(*Builder)) {
    Builder->eraseFromParent();
    return nullptr;
  }

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
           lldb::SBAddress addr(ConstExpr->getValue(), target);
          auto symCtx = target.ResolveSymbolContextForAddress(
                           addr, lldb::eSymbolContextEverything);
          if (symCtx.IsValid() && symCtx.GetSymbol().IsValid())
            TargetFnName = symCtx.GetSymbol().GetDisplayName();
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

  if (IsCrashStart) Builder->setFlag(MachineInstr::CrashStart);

  return &*Builder;
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
    lldb::SBTarget &target, bool HaveDebugInfo, MachineFunction *MF,
    MachineBasicBlock *FirstMBB, StringRef OriginalFunction, DISubprogram *DISP,
    std::unordered_map<std::string, DISubprogram *> &SPs, LLVMContext &Ctx,
    lldb::addr_t CrashStartAddr,
    std::unordered_map<uint64_t, StringRef> &FuncStartSymbols,
    bool IsFnOutOfBt) {
  llvm::outs() << "Decompiling " << OriginalFunction << "\n";

  MachineBasicBlock *MBB = FirstMBB;
  bool PrevBranch = true;
  crash_analyzer::RegSet DefinedRegs;

  lldb_private::ArchSpec arch(TheTriple.normalize());
  lldb::DisassemblerSP Disassembler_sp =
      lldb_private::Disassembler::FindPlugin(arch, nullptr, nullptr);

  // Jumps to be updated with proper targets ( in form of bb).
  // This maps the target address with the jump.
  std::unordered_multimap<uint64_t, MachineInstr *> BranchesToUpdate;

  std::pair<lldb::addr_t, lldb::addr_t> func_range{FuncStart.GetFileAddress(),
                                                   FuncEnd.GetFileAddress()};
  lldb::addr_t FuncLoadAddr = FuncStart.GetLoadAddress(target);

  lldb::DataBufferSP buffer_sp(
      new lldb_private::DataBufferHeap(func_range.second, 0));
  lldb::SBError error;
  target.ReadMemory(FuncStart, buffer_sp->GetBytes(), buffer_sp->GetByteSize(),
                    error);

  lldb_private::DataExtractor Extractor(buffer_sp, target.GetByteOrder(),
                                        target.GetAddressByteSize());
  Disassembler_sp->DecodeInstructions(FuncLoadAddr, Extractor, 0,
                                      Instructions.GetSize(), false, false);

  lldb_private::InstructionList &instruction_list =
      Disassembler_sp->GetInstructionList();
  size_t numInstr = instruction_list.GetSize();
  for (size_t k = 0; k < numInstr; ++k) {
    // This is used for tracking inlined functions.
    // The instrs from such fn will be stored in a .text of another fn.
    auto InstSP = instruction_list.GetInstructionAtIndex(k);
    uint64_t InstAddr = InstSP->GetAddress().GetFileAddress();

    StringRef InlinedFnName = "";

    uint32_t line = 0;
    uint32_t column = 0;
    if (HaveDebugInfo) {
      auto sbInst = Instructions.GetInstructionAtIndex(k);
      line = sbInst.GetAddress().GetLineEntry().GetLine();
      column = sbInst.GetAddress().GetLineEntry().GetColumn();
      if (sbInst.GetAddress().GetBlock().IsInlined()) {
        InlinedFnName = sbInst.GetAddress().GetBlock().GetInlinedName();
        if (!AlreadyDecompiledFns.count(InlinedFnName.str())) {
          auto InlineFnOutOfBt =
             decompileInlinedFnOutOfbt(InlinedFnName, DISP->getFile());
          (void)InlineFnOutOfBt;
        }
      }
    }

    llvm::MCInst Inst;
    auto InstSize = InstSP->GetMCInst(Inst);
    if (InstSize == 0) return false;

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
        if (!OldBB->isSuccessor(MBB)) OldBB->addSuccessor(MBB);
        MF->push_back(MBB);
      }

      // This is used to prevent wrong DI SP attached to inlined
      // instructions.
      if (InlinedFnName != "") {
        if (SPs.count(InlinedFnName)) DISP = SPs[InlinedFnName];
      } else {
        if (SPs.count(OriginalFunction)) DISP = SPs[OriginalFunction];
      }

      auto DILoc = DILocation::get(Ctx, line, column, DISP);
      DebugLoc Loc = DebugLoc(DILoc);
      // For the functions out of backtrace we should analize whole
      // function, so crash-start flag should go at the end of the fn.
      if (IsFnOutOfBt && k == (numInstr - 1))
        MI = addInstr(MF, MBB, Inst, &Loc, true,
                      DefinedRegs, FuncStartSymbols, target);
      else
        MI = addInstr(MF, MBB, Inst, &Loc, CrashStartAddr == Addr.Address,
                      DefinedRegs, FuncStartSymbols, target);

      if (MI) {
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

  return true;
}

llvm::Error crash_analyzer::Decompiler::run(
    StringRef InputFile, SmallVectorImpl<StringRef> &functionsFromCoreFile,
    FrameToRegsMap &FrameToRegs, SmallVectorImpl<BlameFunction> &BlameTrace,
    std::map<llvm::StringRef, lldb::SBFrame> &FrameInfo, lldb::SBTarget &target,
    Triple TheTriple) {
  llvm::outs() << "Decompiling...\n";

  LLVMTargetMachine &LLVMTM = static_cast<LLVMTargetMachine &>(*TM.get());

  Module = createModule(Ctx, TM->createDataLayout(), InputFile);

  mTriple = TheTriple;

  MMI = new MachineModuleInfo(&LLVMTM);
  if (!MMI)
    // FIXME: emit an error here.
    return Error::success();

  MMI->initialize();

  // Map of the functions we are about to decompile.
  std::unordered_set<std::string> FunctionsToDecompile;
  for (StringRef f : functionsFromCoreFile)
    FunctionsToDecompile.insert(f.str());

  // Create Debug Info.
  DIBuilder DIB(*Module);

  for (auto &frame : FrameInfo) {
    auto FuncAddr = frame.second.GetFunction().GetStartAddress().GetFileAddress();
    FuncStartSymbols[FuncAddr] = frame.first;
  }

  for (auto &frame : FrameInfo) {
    // Skip artificial frames.
    if (frame.second.IsArtificial())
      continue;

    lldb::SBInstructionList Instructions;
    lldb::SBAddress FuncStart, FuncEnd;
    bool HaveDebugInfo = false;

    auto Func = frame.second.GetFunction();
    if (!Func) {
      WithColor::warning()
          << "No debugging info found for a function from backtrace. "
          << "Please provide debugging info for the exe and all libraries.\n";
      auto Symbol = frame.second.GetSymbol();
      if (!Symbol) {
        WithColor::warning()
            << "No symbols found for a function "
            << "from backtrace. Please "
            << "provide symbols for the exe and all libraries.\n";
        continue;
      }
      Instructions = Symbol.GetInstructions(target);
      FuncStart = Symbol.GetStartAddress();
      FuncEnd = Symbol.GetEndAddress();
    } else {
      HaveDebugInfo = true;
      Instructions = Func.GetInstructions(target);
      FuncStart = Func.GetStartAddress();
      FuncEnd = Func.GetEndAddress();
    }

    std::string FileDirInfo, FileNameInfo, AbsFileName;
    if (HaveDebugInfo) {
      FileDirInfo = frame.second.GetCompileUnit().GetFileSpec().GetDirectory();
      FileNameInfo = frame.second.GetCompileUnit().GetFileSpec().GetFilename();
      AbsFileName =
          (Twine(FileDirInfo) + Twine("/") + Twine(FileNameInfo)).str();
    }

    if (ShowDisassembly) {
      outs() << "\nDissasemble of the functions from backtrace:\n";
      outs() << frame.second.Disassemble();
    }

    // Create MFs.
    MachineFunction *MF = nullptr;
    MachineBasicBlock *MBB = nullptr;
    DISubprogram *DISP = nullptr;
    std::string InstrAddr;
    unsigned AddrValue = 0;

    StringRef FunctionName = frame.first;

    MF = &createMF(FunctionName);
    MBB = MF->CreateMachineBasicBlock();
    MF->push_back(MBB);

    DIFile *File = nullptr;
    DICompileUnit *CU = nullptr;

    if (MF && HaveDebugInfo) {
      if (!CUs.count(AbsFileName)) {
        File = DIB.createFile(AbsFileName, "/");
        CU = DIB.createCompileUnit(
            dwarf::DW_LANG_C, File, "llvm-crash-analyzer", /*isOptimized=*/true, "",
            0, StringRef(), DICompileUnit::DebugEmissionKind::FullDebug, 0,
            true, false, DICompileUnit::DebugNameTableKind::Default, false,
            true);
        CUs.insert({AbsFileName, std::make_pair(File, CU)});
      } else {
        File = CUs[AbsFileName].first;
        CU = CUs[AbsFileName].second;
      }
    }

    // Once we created the DI file, create DI subprogram.
    if (HaveDebugInfo && !DISP && File && CU && MF) {
      auto &F = MF->getFunction();
      auto SPType = DIB.createSubroutineType(DIB.getOrCreateTypeArray(None));
      DISubprogram::DISPFlags SPFlags =
          DISubprogram::SPFlagDefinition | DISubprogram::SPFlagOptimized;
      auto SP = DIB.createFunction(CU, F.getName(), F.getName(), File, 1,
                                   SPType, 1, DINode::FlagZero, SPFlags);
      (const_cast<Function *>(&F))->setSubprogram(SP);
      DISP = SP;
      DIB.finalizeSubprogram(SP);
      if (!SPs.count(FunctionName))
        SPs.insert({FunctionName, SP});
    }

    // Here we stop decompiling inlined functions. This MF is dummy fn,
    // since the instructions of will be in the MF where it got inlined. We need
    // this MF in order to attach DISubprogram on it.
    // TODO: We assume that inlined functions is in the same compilation unit as
    // the function where it got inlined, but there is Cross-CU inlining by using
    // LTO, but it will be handled as future work.
    if (frame.second.IsInlined()) {
      auto TII = MF->getSubtarget().getInstrInfo();
      MCInst NopInst;
      TII->getNoop(NopInst);
      const unsigned Opcode = NopInst.getOpcode();
      const MCInstrDesc &MCID = MII->get(Opcode);
      BuildMI(MBB, DebugLoc(), MCID);

      // Map the fn from backtrace to the MF.
      // FIXME: Improve this by using a hash map.
      int index = 0;
      for (auto &f : BlameTrace) {
        if (f.Name == FunctionName) {
          // Crash order starts from 1.
          MF->setCrashOrder(index + 1);
          f.MF = MF;
          break;
        }
        ++index;
      }

      continue;
    }

    // Get the address of the latest instruction executed within a frame.
    auto Regs = FrameToRegs.find(FunctionName);
    // Get the value of $rip register, since it holds the address of current
    // instr being executed.
    for (auto &reg : Regs->second) {
      if (reg.regName == "rip") {
        InstrAddr = reg.regValue;
        std::istringstream converter(InstrAddr);
        converter >> std::hex >> AddrValue;
        break;
      }
    }

    // Fill up the register-memory state into coresponding MF attributes.
    MachineFunction::RegisterCrashInfo regInfo;
    for (auto &reg : Regs->second)
      regInfo.push_back({reg.regName, reg.regValue});
    MF->addCrashRegInfo(regInfo);

    if (!DecodeIntrsToMIR(TheTriple, Instructions, FuncStart, FuncEnd, target, HaveDebugInfo,
                     MF, MBB, frame.first, DISP, SPs, Ctx, frame.second.GetPC(),
                     FuncStartSymbols))
      return make_error<StringError>("unable to decompile an instruction",
                                     inconvertibleErrorCode());

    LLVM_DEBUG(if (MF) {
      dbgs() << "Decompiled MF:\n";
      MF->dump();
    });

    // Map the fn from backtrace to the MF.
    // FIXME: Improve this by using a hash map.
    int index = 0;
    for (auto &f : BlameTrace) {
      if (f.Name == FunctionName) {
        // Crash order starts from 1.
        MF->setCrashOrder(index + 1);
        f.MF = MF;
        break;
      }
      ++index;
    }

    // Remove the function from working set.
    FunctionsToDecompile.erase(FunctionName);
    // If we decompiled all the functions, break the loop.
    if (FunctionsToDecompile.empty()) break;
  }

  // Create MFs for function out of backtrace.
  // NOTE: Always recalculate the size() for the FunctionsThatAreNotInBT
  // since we might have nested calls that may be blame ones.

  // This will be used for mapping already decompiled functions, so we do not
  // do it twice.
  // FIXME: This is now handled in the decompileOnDemand() which is being called
  // during Taint Analysis.
  SmallSet<long, 8> AlreadyDecompiledMFs;
  if (DecompileFnsOutOfbt) {
    for (size_t i = 0; i < FunctionsThatAreNotInBT.size(); i++) {
      //break;
      auto NonBTFnAddr = FunctionsThatAreNotInBT[i];
      if (AlreadyDecompiledMFs.count(NonBTFnAddr))
        continue;
      AlreadyDecompiledMFs.insert(NonBTFnAddr);
      lldb::SBAddress addr(NonBTFnAddr, target);
      auto symCtx = target.ResolveSymbolContextForAddress(
                        addr, lldb::eSymbolContextEverything);
      if (!(symCtx.IsValid() && symCtx.GetSymbol().IsValid()))
        continue;
      lldb::SBInstructionList Instructions;
      lldb::SBAddress FuncStart, FuncEnd;
      auto Symbol = symCtx.GetSymbol();
      Instructions = Symbol.GetInstructions(target);
      FuncStart = Symbol.GetStartAddress();
      FuncEnd = Symbol.GetEndAddress();

      bool HasDbgInfo = false;
      auto Fn = FuncStart.GetFunction();
      MachineFunction *MF = &createMF(symCtx.GetSymbol().GetDisplayName());
      MachineBasicBlock *MBB = MF->CreateMachineBasicBlock();
      MF->push_back(MBB);

      DISubprogram *SP = nullptr;

      // Handle debug info if this comes from another module.
      if (Fn) {
        HasDbgInfo = true;
        DIFile *File = nullptr;
        DICompileUnit *CU = nullptr;
        std::string FileDirInfo, FileNameInfo, AbsFileName;
        FileDirInfo = FuncStart.GetCompileUnit().GetFileSpec().GetDirectory();
        FileNameInfo = FuncStart.GetCompileUnit().GetFileSpec().GetFilename();
        AbsFileName =
            (Twine(FileDirInfo) + Twine("/") + Twine(FileNameInfo)).str();

        if (!CUs.count(AbsFileName)) {
          File = DIB.createFile(AbsFileName, "/");
          CU = DIB.createCompileUnit(
              dwarf::DW_LANG_C, File, "llvm-crash-analyzer", /*isOptimized=*/true, "",
              0, StringRef(), DICompileUnit::DebugEmissionKind::FullDebug, 0,
              true, false, DICompileUnit::DebugNameTableKind::Default, false,
              true);
          CUs.insert({AbsFileName, std::make_pair(File, CU)});
        } else {
          File = CUs[AbsFileName].first;
          CU = CUs[AbsFileName].second;
        }

        auto &F = MF->getFunction();
        auto SPType = DIB.createSubroutineType(DIB.getOrCreateTypeArray(None));
        DISubprogram::DISPFlags SPFlags =
            DISubprogram::SPFlagDefinition | DISubprogram::SPFlagOptimized;
        auto sp = DIB.createFunction(CU, F.getName(), F.getName(), File, 1,
                                     SPType, 1, DINode::FlagZero, SPFlags);
        (const_cast<Function *>(&F))->setSubprogram(sp);
        SP = sp;
        DIB.finalizeSubprogram(SP);
        if (!SPs.count(MF->getName()))
          SPs.insert({MF->getName(), SP});
      }

      if (!DecodeIntrsToMIR(TheTriple, Instructions, FuncStart, FuncEnd, target, HasDbgInfo,
                       MF, MBB, symCtx.GetSymbol().GetDisplayName(), SP,
                       SPs, Ctx, 0, FuncStartSymbols, true /*IsFnOutOfBt*/))
        return make_error<StringError>("unable to decompile an instruction",
                                       inconvertibleErrorCode());
      BlameTrace.push_back({symCtx.GetSymbol().GetDisplayName(), MF});
      // Functions that are out of backtrace have 0 crash order.
      MF->setCrashOrder(0);
    }
  }

  // Run FixRegStateFlags pass for each basic block.
  FixRegStateFlags FRSF;
  for (auto &f : BlameTrace) {
    if (f.MF) FRSF.run(*(f.MF));
  }

  MMI->finalize();

  if (PrintDecMIR != "") {
    StringRef file_name = PrintDecMIR;
    if (!file_name.endswith(".mir")) {
      errs() << "MIR file must be with '.mir' extension.\n";
      // TODO: return real error here.
      return Error::success();
    }

    std::error_code EC;
    raw_fd_ostream OS_FILE{PrintDecMIR, EC, sys::fs::OF_Text};
    if (EC) {
      errs() << "Could not open file: " << EC.message() << ", " << PrintDecMIR
             << '\n';
      return errorCodeToError(EC);
    }
    printMIR(OS_FILE, *Module.get());
    for (auto &f : BlameTrace) {
      if (f.MF) printMIR(OS_FILE, *f.MF);
    }
  }

  // Rememer the MFs for analysis.
  for (auto &F : *(Module.get())) {
    auto MF = MMI->getMachineFunction(F);
    if (MF) BlameMFs.push_back(MF);
  }

  llvm::outs() << "Decompiled.\n";
  return Error::success();
}

MachineFunction*
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
  auto &F = MF->getFunction();
  auto SPType = DIB.createSubroutineType(DIB.getOrCreateTypeArray(None));
  DISubprogram::DISPFlags SPFlags =
      DISubprogram::SPFlagDefinition | DISubprogram::SPFlagOptimized;
  auto SP = DIB.createFunction(CU, F.getName(), F.getName(), File, 1,
                               SPType, 1, DINode::FlagZero, SPFlags);
  (const_cast<Function *>(&F))->setSubprogram(SP);
  DIB.finalizeSubprogram(SP);
  if (!SPs.count(TargetName))
    SPs.insert({TargetName, SP});

  auto TII = MF->getSubtarget().getInstrInfo();
  MCInst NopInst;
  TII->getNoop(NopInst);
  const unsigned Opcode = NopInst.getOpcode();
  const MCInstrDesc &MCID = MII->get(Opcode);
  BuildMI(MBB, DebugLoc(), MCID);
  MF->setCrashOrder(0);
  AlreadyDecompiledFns.insert({TargetName.str(), MF});
  return MF;
}

// TODO: Remove duplicated code from this function.
MachineFunction* crash_analyzer::Decompiler::decompileOnDemand(StringRef TargetName) {
  if (TargetName == "")
    return nullptr;

  if (!target)
    return nullptr;

  if (AlreadyDecompiledFns.count(TargetName))
    return AlreadyDecompiledFns[TargetName];

  auto symCtxs = target->FindFunctions(TargetName.data());
  if (symCtxs.GetSize() != 1) {
    LLVM_DEBUG(
      llvm::dbgs() << "Multiple symbols found for: " << TargetName << '\n');
    return nullptr;
  }

  auto symCtx = symCtxs.GetContextAtIndex(0);
  if (!(symCtx.IsValid() && symCtx.GetSymbol().IsValid())) {
    LLVM_DEBUG(
      llvm::dbgs() << "Symbols isn't valid: " << TargetName << '\n');
    return nullptr;
  }

  lldb::SBInstructionList Instructions;
  lldb::SBAddress FuncStart, FuncEnd;
  auto Symbol = symCtx.GetSymbol();
  Instructions = Symbol.GetInstructions(*target);
  FuncStart = Symbol.GetStartAddress();
  FuncEnd = Symbol.GetEndAddress();

  bool HasDbgInfo = false;
  auto Fn = FuncStart.GetFunction();
  MachineFunction *MF = &createMF(symCtx.GetSymbol().GetDisplayName());
  MachineBasicBlock *MBB = MF->CreateMachineBasicBlock();
  MF->push_back(MBB);

  DISubprogram *SP = nullptr;

  // Create Debug Info.
  DIBuilder DIB(*Module);

  // Handle debug info if this comes from another module.
  if (Fn) {
    HasDbgInfo = true;
    DIFile *File = nullptr;
    DICompileUnit *CU = nullptr;
    std::string FileDirInfo, FileNameInfo, AbsFileName;
    FileDirInfo = FuncStart.GetCompileUnit().GetFileSpec().GetDirectory();
    FileNameInfo = FuncStart.GetCompileUnit().GetFileSpec().GetFilename();
    AbsFileName =
        (Twine(FileDirInfo) + Twine("/") + Twine(FileNameInfo)).str();

    if (!CUs.count(AbsFileName)) {
      File = DIB.createFile(AbsFileName, "/");
      CU = DIB.createCompileUnit(
          dwarf::DW_LANG_C, File, "llvm-crash-analyzer", /*isOptimized=*/true, "",
          0, StringRef(), DICompileUnit::DebugEmissionKind::FullDebug, 0,
          true, false, DICompileUnit::DebugNameTableKind::Default, false,
          true);
      CUs.insert({AbsFileName, std::make_pair(File, CU)});
    } else {
      File = CUs[AbsFileName].first;
      CU = CUs[AbsFileName].second;
    }

    auto &F = MF->getFunction();
    auto SPType = DIB.createSubroutineType(DIB.getOrCreateTypeArray(None));
    DISubprogram::DISPFlags SPFlags =
        DISubprogram::SPFlagDefinition | DISubprogram::SPFlagOptimized;
    auto sp = DIB.createFunction(CU, F.getName(), F.getName(), File, 1,
                                 SPType, 1, DINode::FlagZero, SPFlags);
    (const_cast<Function *>(&F))->setSubprogram(sp);
    SP = sp;
    DIB.finalizeSubprogram(SP);
    if (!SPs.count(MF->getName()))
      SPs.insert({MF->getName(), SP});
  }

  if (!DecodeIntrsToMIR(mTriple, Instructions, FuncStart, FuncEnd, *target, HasDbgInfo,
                   MF, MBB, symCtx.GetSymbol().GetDisplayName(), SP,
                   SPs, Ctx, 0, FuncStartSymbols, true /*IsFnOutOfBt*/))
    return nullptr;

  // Functions that are out of backtrace have 0 crash order.
  MF->setCrashOrder(0);

  return MF;
}
