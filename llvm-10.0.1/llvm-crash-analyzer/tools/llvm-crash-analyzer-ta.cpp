//===- llvm-crash-analyzer-ta.cpp -------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements the entry point for the llvm-crash-analyzer-ta tool, used for
// testing purposes only. It performs the Taint Analysis on the MIR file
// provided.
//
//===----------------------------------------------------------------------===//

#include "Analysis/TaintAnalysis.h"
#include "Decompiler/Decompiler.h"
#include "Target/CATargetInfo.h"

#include "llvm/ADT/Triple.h"
#include "llvm/CodeGen/MIRParser/MIRParser.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"

using namespace llvm;
using namespace crash_analyzer;

#define DEBUG_TYPE "llvm-crash-analyzer-ta"

/// @}
/// Command line options.
/// @{
namespace {
using namespace cl;
OptionCategory CrashAnalyzerTA("Specific Options");
static opt<bool> Help("h", desc("Alias for -help"), Hidden,
                      cat(CrashAnalyzerTA));
static opt<std::string>
    InputFilename(Positional, desc("<input mir file>"), cat(CrashAnalyzerTA));
static opt<std::string>
    OutputFilename("out-file", cl::init("-"),
                   cl::desc("Redirect output to the specified file"),
                   cl::value_desc("filename"),
                   cat(CrashAnalyzerTA));
static alias OutputFilenameAlias("o", desc("Alias for -out-file"),
                                 aliasopt(OutputFilename),
                                 cat(CrashAnalyzerTA));
} // namespace
/// @}

static void setFunctionAttributes(StringRef CPU, StringRef Features,
                                  Function &F) {
  // TODO: set unction attributes of function if needed.
}

int main(int argc, char **argv) {
  llvm::outs() << "Crash Analyzer -- Taint Analysis\n";

  InitLLVM X(argc, argv);
  InitializeAllTargetInfos();
  InitializeAllTargetMCs();
  InitializeAllTargets();

  HideUnrelatedOptions({&CrashAnalyzerTA});
  cl::ParseCommandLineOptions(argc, argv, "crash analyzer TA\n");
  if (Help) {
    PrintHelpMessage(false, true);
    return 0;
  }

  if (InputFilename == "") {
    WithColor::error(errs()) << "no input file\n";
    exit(1);
  }

  StringRef IFN = InputFilename;
  if (!IFN.endswith(".mir")) {
    WithColor::error(errs()) << "input file must be MIR file\n";
    exit(1);
  }

  // FIXME: Currently, we don't set any of IR Function attributes.
  std::string CPUStr = "", FeaturesStr = "";
  // Set attributes on functions as loaded from MIR from command line arguments.
  auto setMIRFunctionAttributes = [&CPUStr, &FeaturesStr](Function &F) {
    setFunctionAttributes(CPUStr, FeaturesStr, F);
  };

  LLVMContext Context;
  SMDiagnostic Err;
  std::unique_ptr<Module> M;
  std::unique_ptr<MIRParser> MIR;
  MachineModuleInfo *MMI;

  MIR = createMIRParserFromFile(InputFilename, Err, Context,
                                setMIRFunctionAttributes);
  if (!MIR) {
    WithColor::error(errs()) << "unable to parse the mir input file\n";
    exit(1);
  }

  M = MIR->parseIRModule();

  // Read the Triple from the MIR file, if not available, use default triple.
  Triple TheTriple(M->getTargetTriple());
  if (TheTriple.getTriple().empty())
    TheTriple.setTriple(sys::getDefaultTargetTriple());

  std::string ErrorStr;
  std::string TripleName;

  if (!isCATargetSupported(TheTriple)) {
    llvm::errs() << "\n Crash Analyzer TA does NOT support target " << TheTriple.getTriple();
    exit(1);
  }
  CATargetInfo::initializeCATargetInfo(&TheTriple);

  // Get the target.
  const Target *TheTarget =
      TargetRegistry::lookupTarget(TripleName, TheTriple, ErrorStr);
  if (!TheTarget) {
    WithColor::error(errs()) << "no target available\n";
    exit(1);
  }

  TripleName = TheTriple.getTriple();
  std::unique_ptr<TargetMachine> TM;
  TM.reset(TheTarget->createTargetMachine(TripleName, "", "", TargetOptions(), None));
  if (!TM) {
    WithColor::error(errs()) << "unable to create TM\n";
    exit(1);
  }


  M->setDataLayout(TM->createDataLayout());

  if (!M) {
    WithColor::error(errs()) << "unable to parse IR part for input file\n";
    exit(1);
  }

  LLVMTargetMachine &LLVMTM = static_cast<LLVMTargetMachine &>(*TM.get());
  MMI = new MachineModuleInfo(&LLVMTM);
  if (!MMI) {
    WithColor::error(errs()) << "unable to create MIR module for input file\n";
    exit(1);
  }
  MMI->initialize();

  if (MIR->parseMachineFunctions(*M, *MMI)) {
    WithColor::error(errs()) << "unable to parse MIR functions from input file\n";
    exit(1);
  }
  MMI->finalize();

  WithColor::warning(errs())
      << "This tool is deprecated until we decide how to "
         "use corefile content here.\n";

  crash_analyzer::TaintAnalysis TA(true);
  BlameModule BlameTrace;
  SmallVector<MachineFunction *, 8> BlameMFs;

  for (auto &F : *(M.get())) {
    auto MF = MMI->getMachineFunction(F);
    if (MF)
      BlameMFs.push_back(MF);
  }

  // Create BlameModule with the order occured in the backtrace.
  unsigned index = 1;
  while (true) {
    MachineFunction *MF = nullptr;
    for (auto &f : BlameMFs) {
      if (f->getCrashOrder() == index) {
        MF = f;
        ++index;
        break;
      }
    }

    if (!MF)
      break;

    BlameTrace.push_back({MF->getName(), MF});
  }

  // Get functions that are out of backtrace.
  for (auto &f : BlameMFs)
    if (f->getCrashOrder() == 0)
      BlameTrace.push_back({f->getName(), f});

  if (!TA.runOnBlameModule(BlameTrace))
    llvm::outs() << "\nRESULT: FAIL\n";
  else
    llvm::outs() << "\nRESULT: SUCCESS\n";

  return 0;
}
