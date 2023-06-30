//===- CoreFile.h ------------------------------------------------*- C++ -*===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef CB_COREFILE_
#define CB_COREFILE_

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Support/WithColor.h"

#include "lldb/API/SBDebugger.h"
#include "lldb/API/SBFrame.h"
#include "lldb/API/SBInstruction.h"
#include "lldb/API/SBProcess.h"
#include "lldb/API/SBTarget.h"

#include <map>
#include <vector>

struct RegInfo {
  std::string regName;
  std::string regValue;
  RegInfo(const char *regName1, const char *regValue1) {
    if (regName1)
      std::copy(regName1, regName1 + strlen(regName1),
                std::back_inserter(regName));
    else
      regName = "";

    if (regValue1)
      std::copy(regValue1, regValue1 + strlen(regValue1),
                std::back_inserter(regValue));
    else
      regValue = "";
  }
};

using FrameToRegsMap = std::map<llvm::StringRef, std::vector<RegInfo>>;

namespace lldb {
namespace crash_analyzer {

class CoreFile {
  unsigned NumOfFrames = 0;
  const char *name;
  lldb::SBTarget target;
  lldb::SBDebugger debugger;
  lldb::SBProcess process;
  llvm::SmallVector<llvm::StringRef, 8> FunctionsFromBacktrace;
  FrameToRegsMap GPRs;
  std::map<llvm::StringRef, lldb::SBFrame> FrameInfo;

public:
  CoreFile(llvm::StringRef name, llvm::StringRef InputFileName,
           llvm::StringRef SysRoot,
           llvm::StringRef ModulesPath)
      : name(name.data()) {
    lldb::SBDebugger::Initialize();
    debugger = lldb::SBDebugger::Create();
    if (SysRoot != "") {
      std::string SysRootCommand = "platform select --sysroot ";
      SysRootCommand = SysRootCommand + SysRoot.str() + " remote-linux";
      debugger.HandleCommand(SysRootCommand.c_str());
    }

    if (ModulesPath != "") {
      llvm::SmallVector<llvm::StringRef, 8> ModulesPaths;
      ModulesPath.split(ModulesPaths, ':');
      std::string paths = "";
      for (auto &p : ModulesPaths) {
        std::string path = p.str();
        paths += path;
        paths += " ";
      }

      std::string AddSearchPathCommand =
          llvm::Twine("settings set target.exec-search-paths " + paths).str();
      debugger.HandleCommand(AddSearchPathCommand.c_str());
    }

    target = debugger.CreateTarget(InputFileName.data());

    if (!target.IsValid()) {
      llvm::WithColor::error() << "invalid target inside debugger\n";
      return;
    }

    process = target.LoadCore(name.data());
    if (!process.IsValid()) {
      llvm::WithColor::error() << "invalid core-file\n";
      return;
    }

    FunctionsFromBacktrace = {};
    FrameInfo = {};
  }

  ~CoreFile() {
    lldb::SBDebugger::Destroy(debugger);
    lldb::SBDebugger::Terminate();
  }

  bool read(llvm::StringRef SolibSearchPath);
  llvm::SmallVector<llvm::StringRef, 8> &getFunctionsFromBacktrace() {
    return FunctionsFromBacktrace;
  }

  // Handle General Purpose Registers.
  FrameToRegsMap &getGRPsFromFrame() { return GPRs; }
  void insertIntoGPRsFromFrame(llvm::StringRef frame, std::vector<RegInfo> &Regs) {
    GPRs.insert(std::make_pair(frame, Regs));
  }

  void rememberSBFrame(llvm::StringRef frame, lldb::SBFrame f) {
    FrameInfo.insert(std::make_pair(frame, f));
  }
  std::map<llvm::StringRef, lldb::SBFrame> &getFrameInfo() { return FrameInfo; }

  void setNumOfFrames(unsigned frames) { NumOfFrames = frames; }
  unsigned getNumOfFrames() { return NumOfFrames; }

  lldb::SBTarget &getTarget() { return target; }
};

} // namespace lldb_crash_analyzer
} // namespace llvm

#endif
