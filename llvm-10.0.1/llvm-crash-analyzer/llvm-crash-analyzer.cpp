//===- llvm-crash-analyzer.cpp ---------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements the entry point for the crash analyzer tool.
//
//===----------------------------------------------------------------------===//

#include "Decompiler/Decompiler.h"
#include "CoreFile/CoreFile.h"
#include "Analysis/TaintAnalysis.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/Triple.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace crash_analyzer;

#define DEBUG_TYPE "llvm-crash-analyzer"

/// @}
/// Command line options.
/// @{
namespace {
using namespace cl;
OptionCategory CrashAnalyzer("Specific Options");
static opt<bool> Help("h", desc("Alias for -help"), Hidden,
                      cat(CrashAnalyzer));
static opt<std::string>
    InputFilename(Positional, desc("<input file>"), cat(CrashAnalyzer));
static opt<std::string>
    OutputFilename("out-file", cl::init("-"),
                   cl::desc("Redirect output to the specified file"),
                   cl::value_desc("filename"),
                   cat(CrashAnalyzer));
static alias OutputFilenameAlias("o", desc("Alias for -out-file"),
                                 aliasopt(OutputFilename),
                                 cat(CrashAnalyzer));
static opt<std::string> CoreFileName("core-file", cl::init(""),
                                     cl::desc("<core-file>"),
                                     cl::value_desc("corefilename"),
                                     cat(CrashAnalyzer));
static opt<std::string> SysRoot("sysroot", cl::init(""),
                                cl::desc("<path>"),
                                cl::value_desc("sysrootpath"),
                                cat(CrashAnalyzer));
static opt<std::string> SolibSearchPath("solib-search-path", cl::init(""),
                                cl::desc("<paths>"),
                                cl::value_desc("solibsearchpath"),
                                cat(CrashAnalyzer));
static opt<std::string> ModulesPath("modules-path", cl::init(""),
                                cl::desc("<paths>"),
                                cl::value_desc("modulespath"),
                                cat(CrashAnalyzer));
static opt<std::string> PrintTaintValueFlowAsDot(
    "print-taint-value-flow-as-dot", cl::init(""),
    cl::desc("Print Taint DF Graph as DOT. "
             "Please use `$ dot <dot-file-name> -Tpng -o "
              "<dot-file-name>.png` to see the graph in form of picture."),
    cl::value_desc("<dot-file-name>"),
    cat(CrashAnalyzer));

static opt<bool> PrintPotentialCrashCauseLocation(
    "print-potential-crash-cause-loc", cl::init(false),
    cl::desc("Print line:column that could be the cause of the crash."),
    cat(CrashAnalyzer));
} // namespace
/// @}
//===----------------------------------------------------------------------===//

static void error(StringRef Prefix, std::error_code EC) {
  if (!EC)
    return;
  WithColor::error() << Prefix << ": " << EC.message() << "\n";
  exit(1);
}

int main(int argc, char **argv) {
  llvm::outs() << "Crash Analyzer -- crash analyzer utility\n";

  InitLLVM X(argc, argv);
  InitializeAllTargetInfos();
  InitializeAllTargetMCs();
  InitializeAllTargets();
  InitializeAllDisassemblers();

  HideUnrelatedOptions({&CrashAnalyzer});
  cl::ParseCommandLineOptions(argc, argv, "crash analyzer\n");
  if (Help) {
    PrintHelpMessage(false, true);
    return 0;
  }

  if (InputFilename == "") {
    WithColor::error(errs()) << "no input file\n";
    exit(1);
  }

  if (CoreFileName == "") {
    WithColor::error(errs()) << "no core-file specified\n";
    exit(1);
  }

  std::error_code EC;
  ToolOutputFile OutputFile(OutputFilename, EC, sys::fs::OF_None);
  error("Unable to open output file" + OutputFilename, EC);
  // Don't remove output file if we exit with an error.
  OutputFile.keep();
  int exit_code = 0;

  auto handleError = [](Error &&e) {
    handleAllErrors(std::move(e), [](ErrorInfoBase &eib) {
      WithColor::error() << eib.message() << "\n";
    });
  };

  // Read the symbols from core file (e.g. function names from crash backtrace).
  // TODO: Read registers and memory state from core-file.
  CoreFile coreFile(CoreFileName, InputFilename, SysRoot, ModulesPath);
  if (!coreFile.read(SolibSearchPath)) {
    llvm::outs() << "\nRESULT: FAIL\n";
    return -1;
  }

  // Get the functions from backtrace.
  auto functionsFromCoreFile = coreFile.getFunctionsFromBacktrace();
  auto FrameToRegs = coreFile.getGRPsFromFrame();

  // Implement decompiler.
  Triple Triple(Triple::normalize(sys::getDefaultTargetTriple()));

  auto Decompiler = crash_analyzer::Decompiler::create(Triple);
  if (!Decompiler)
    return 1;
  crash_analyzer::Decompiler *Dec = Decompiler.get().get();

  // This map holds the function-name<->MF mapping from the backtrace
  // (in order the functions were called within the program).
  BlameModule BlameTrace;

  // Init the blame trace map.
  for (StringRef Fn : functionsFromCoreFile)
    BlameTrace.push_back({Fn, nullptr});

  auto Err = Dec->run(InputFilename, functionsFromCoreFile, FrameToRegs,
                      BlameTrace, coreFile.getFrameInfo(),
                      coreFile.getTarget(), Triple);
  if (Err) {
    handleError(std::move(Err));
    return 0;
  }

  LLVM_DEBUG(for (auto &f : BlameTrace) {
    llvm::dbgs() << "** fn: " << f.Name << "\n";
    if (f.MF)
      f.MF->dump();
    else
      llvm::dbgs() << "No code generated for " << f.Name << "\n";
  });

  // Run the analysis.
  StringRef DotFileName = "";
  if (PrintTaintValueFlowAsDot != "") {
    DotFileName = PrintTaintValueFlowAsDot;
    if (!DotFileName.endswith(".dot") && !DotFileName.endswith(".gv")) {
      errs() << "DOT file must have `.dot` or `.gv` extension.\n";
      return 0;
    }
  }

  crash_analyzer::TaintAnalysis TA(DotFileName,
                                   PrintPotentialCrashCauseLocation);
  Dec->setTarget(&coreFile.getTarget());
  TA.setDecompiler(Dec);
  TA.runOnBlameModule(BlameTrace);

  return exit_code;
}
