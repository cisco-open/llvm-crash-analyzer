//===- CoreFile.cpp -------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements crash blamer core file loading.
//
//===----------------------------------------------------------------------===//

#include "CoreFile/CoreFile.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#include "lldb/API/SBFileSpec.h"
#include "lldb/API/SBThread.h"
#include "lldb/Utility/ConstString.h"
#include "lldb/Utility/FileSpec.h"
#include "lldb/lldb-forward.h"

using namespace llvm;
using namespace lldb;
using namespace lldb_private;

#define DEBUG_TYPE "crash-blamer-corefile"

static constexpr const char *GPR = "General Purpose Registers";

bool llvm::crash_blamer::CoreFile::read(StringRef InputFile) {
  outs() << "\nLoading core-file " << name << "\n";

  SBThread thread = process.GetSelectedThread();
  if (!thread.IsValid()) {
    WithColor::error() << "invalid thread selected within core-file\n";
    return false;
  }

  int NumOfFrames = thread.GetNumFrames();
  LLVM_DEBUG(dbgs() << "Num of frames " << NumOfFrames << "\n");

  setNumOfFrames(NumOfFrames);

  for (int i = 0; i < NumOfFrames; ++i) {
    auto Frame = thread.GetFrameAtIndex(i);
    if (!Frame.IsValid()) {
      WithColor::error() << "invalid frame found within core-file\n";
      return false;
    }

    LLVM_DEBUG(dbgs() << Frame.GetFunctionName() << "\n");
    StringRef fnName = Frame.GetFunctionName();

    // Get registers state at the point of the crash.
    auto Regs = Frame.GetRegisters();
    auto GPRegss = Regs.GetFirstValueByName(GPR);
    int NumOfGPRegs = GPRegss.GetNumChildren();
    std::vector<RegInfo> RegReads;
    for (int j = 0; j < NumOfGPRegs; ++j) {
      auto Reg = GPRegss.GetChildAtIndex(j);
      if (Reg.GetValue())
        RegReads.push_back({Reg.GetName(), Reg.GetValue()});
      else
        RegReads.push_back({Reg.GetName(), nullptr});
    }

    insertIntoGPRsFromFrame(fnName, RegReads);
    FunctionsFromBacktrace.push_back(fnName);
    rememberSBFrame(fnName, Frame);

    // No need to track __libc_start_main and _start from libc.
    if (fnName == "main")
      break;
  }

  LLVM_DEBUG(auto FrameToRegs = getGRPsFromFrame();
    for (auto &fn : FrameToRegs) {
      dbgs() << "Function: " << fn.first << "\n";
      dbgs() << "Regs:\n";
      for (auto &R : fn.second)
        dbgs() << " reg: " << R.regName << " val: " << R.regValue << "\n";
    });

  outs() << "core-file processed.\n\n";
  return true;
}
