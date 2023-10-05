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
#include "llvm/Support/ErrorOr.h"
#include "llvm/Support/MemoryBuffer.h"

#include "lldb/API/SBDebugger.h"
#include "lldb/API/SBFrame.h"
#include "lldb/API/SBInstruction.h"
#include "lldb/API/SBProcess.h"
#include "lldb/API/SBTarget.h"

#include "CoreProcessWrapper.h"

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
using FunctionsFromBacktraceVec = llvm::SmallVector<llvm::StringRef, 8>;
using FrameInfoVec = std::map<llvm::StringRef, lldb::SBFrame>;
using ThreadFunctionsFromBt = std::map<lldb::tid_t, FunctionsFromBacktraceVec>;
using ThreadFrameToRegsMap = std::map<lldb::tid_t, FrameToRegsMap>;
using ThreadFrameInfo = std::map<lldb::tid_t, FrameInfoVec>;
using ThreadFrameCount = std::map<lldb::tid_t, unsigned int>;

namespace lldb {
namespace crash_analyzer {

class CoreFile {
  const char *name;
  lldb::SBTarget target;
  lldb::SBDebugger debugger;
  lldb::SBProcess process;
  ThreadFunctionsFromBt m_thread_functions;
  ThreadFrameToRegsMap m_thread_gprs;
  ThreadFrameInfo m_thread_frame_info;
  ThreadFrameCount m_thread_num_of_frames;
  std::unique_ptr<CoreProcessWrapper> m_p;

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
    m_p = std::unique_ptr<CoreProcessWrapper>(new CoreProcessWrapper(process));
  }

  ~CoreFile() {
    lldb::SBDebugger::Destroy(debugger);
    lldb::SBDebugger::Terminate();
  }

  bool read(llvm::StringRef SolibSearchPath);

  llvm::SmallVector<llvm::StringRef, 8> &getFunctionsFromBacktrace(
                                                  lldb::tid_t tid) {
    return m_thread_functions[tid];
  }

  // Handle General Purpose Registers.
  FrameToRegsMap &getGPRsFromFrame(lldb::tid_t tid) { 
    return m_thread_gprs[tid];
  }

  std::map<llvm::StringRef, lldb::SBFrame> &getFrameInfo(lldb::tid_t tid) {
    return m_thread_frame_info[tid];
  }

  unsigned getNumOfFrames(lldb::tid_t tid) {
    return m_thread_num_of_frames[tid];
  }

  lldb::SBTarget &getTarget() { return target; }

  lldb::SBProcess &getProcess() { return process; }

  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> GetAuxvData() {
    return m_p->GetAuxvData();
  }
};

} // namespace lldb_crash_analyzer
} // namespace llvm

#endif
