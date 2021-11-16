//===- CoreFile.cpp -------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements crash analyzer core file loading.
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

#include <sys/stat.h>
#include <unistd.h>

using namespace llvm;
using namespace lldb;
using namespace lldb_private;

#define DEBUG_TYPE "llvm-crash-analyzer-corefile"

static constexpr const char *GPR = "General Purpose Registers";

bool llvm::crash_analyzer::CoreFile::read(StringRef SolibSearchPath) {
  outs() << "\nLoading core-file " << name << "\n";

  llvm::SmallVector<StringRef, 8> SysRootPaths;
  SolibSearchPath.split(SysRootPaths, ':');

  SBThread thread = process.GetSelectedThread();
  if (!thread.IsValid()) {
    WithColor::error() << "invalid thread selected within core-file\n";
    return false;
  }

  int NumModules = target.GetNumModules();
  for (int i = 0; i < NumModules; ++i) {
    auto m = target.GetModuleAtIndex(i);
    if (m.GetNumCompileUnits() == 0) {
      StringRef mName = m.GetFileSpec().GetFilename();
      // No need debug info for the vdso.
      if (mName == "[vdso]" || mName == "linux-vdso.so.1")
        continue;

      StringRef SymAddCommand = "target symbols add ";
      std::string FullCommand;

      // Rewrite the module to point to the library from solib-search-path.
      // The first path that contains the library will be used, so the order
      // DOES matter.
      if (SolibSearchPath != "") {
        bool libFound = false;
        char link[1024];
        for (auto &p : SysRootPaths) {
          std::string path = p.str();
          if (!p.endswith("/")) path.push_back('/');

          std::string FullLibPath = Twine(path + mName).str();
          lldb::SBFileSpec FSpecLib(FullLibPath.c_str());
          if (!FSpecLib.Exists()) continue;

          // Check if the module is a sym link.
          struct stat statInfo;
          if (lstat(FullLibPath.c_str(), &statInfo) != -1) {
            if (S_ISLNK(statInfo.st_mode)) {
              ssize_t len;
              if ((len = readlink(FullLibPath.c_str(), link,
                                  sizeof(link) - 1)) != -1)
                link[len] = '\0';
              mName = link;
              FullLibPath = Twine(path + mName).str();
            }
          }

          // Remove old module(libraries), and add the new one, with updated
          // paths.
          target.RemoveModule(m);
          std::string AddModuleCommand =
              Twine("target modules add " + FullLibPath).str();
          target.GetDebugger().HandleCommand(AddModuleCommand.c_str());

          std::string FullPathLibDebug = Twine(FullLibPath + ".debug").str();
          lldb::SBFileSpec FSpecLibDebug(FullPathLibDebug.c_str());
          if (FSpecLibDebug.Exists()) {
            FullCommand = Twine(SymAddCommand + Twine(FullPathLibDebug)).str();
            target.GetDebugger().HandleCommand(FullCommand.c_str());
            libFound = true;
            break;
          }

          // Symbols could be in .debug/ directory.
          std::string FullPathLibDebugInDbgDir =
              Twine(path + ".debug/" + mName).str();
          lldb::SBFileSpec FSpecDebugInDbgDir(FullPathLibDebugInDbgDir.c_str());
          if (FSpecDebugInDbgDir.Exists()) {
            FullCommand =
                Twine(SymAddCommand + Twine(FullPathLibDebugInDbgDir)).str();
            target.GetDebugger().HandleCommand(FullCommand.c_str());
            libFound = true;
            break;
          }

          WithColor::warning()
              << "No debugging symbols found in " << mName << "\n";
          continue;
        }

        if (libFound) continue;

        WithColor::warning()
            << "No debugging symbols found in " << mName << "\n";
        continue;
      }

      auto Dir = m.GetFileSpec().GetDirectory();
      if (!Dir) Dir = "";

      // Try to find debug symbols if the .gnu_debuglink was not set.

      // Check If the module has .debug file in the dir.
      std::string FullPathDebug = Twine(Dir + Twine("/") + mName + ".debug").str();
      lldb::SBFileSpec FspecDebug(FullPathDebug.c_str());
      if (FspecDebug.Exists()) {
        FullCommand =
            Twine(SymAddCommand + Twine(FullPathDebug)).str();
        target.GetDebugger().HandleCommand(FullCommand.c_str());
        continue;
      }
      // Symbols could be in .debug/ directory.
      FullPathDebug = Twine(Dir + Twine(".debug/") + mName).str();
      lldb::SBFileSpec FSpecDebugInDbgDir(FullPathDebug.c_str());
      if (FSpecDebugInDbgDir.Exists()) {
        FullCommand =
          Twine(SymAddCommand + Twine(FullPathDebug)).str();
        target.GetDebugger().HandleCommand(FullCommand.c_str());
        continue;
      }

      WithColor::warning() << "No debugging symbols found in " << mName << "\n";
    }
  }

  int NumOfFrames = thread.GetNumFrames();
  LLVM_DEBUG(dbgs() << "Num of frames " << NumOfFrames << "\n");

  setNumOfFrames(NumOfFrames);

  // There are some cases where debug info for frames is broken,
  // so backtraces can be very long, so we want to skip such cases
  // with this.
  if (NumOfFrames > 64) {
    WithColor::error() << "backtrace is too long(" << NumOfFrames
                       << " frames)\n";
    return false;
  }

  for (int i = 0; i < NumOfFrames; ++i) {
    auto Frame = thread.GetFrameAtIndex(i);
    if (!Frame.IsValid()) {
      WithColor::error() << "invalid frame found within core-file\n";
      return false;
    }

    LLVM_DEBUG(dbgs() << "#" << i << " " << Frame.GetFunctionName() << "\n");
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
    // FIXME:
    //   1) POLARIS has its own version of main(), and the start
    //      function name is different from main(), so this might
    //      not be the right way. We should check if the next frame
    //      is __libc_start_main() and then stop there.
    //   2) I am seeing that bellow __be_unix_suspend() in the POLARIS
    //      corefiles, there is no symbols and frames reported in decoder.
    if (fnName == "main" || fnName == "__be_unix_suspend")
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
