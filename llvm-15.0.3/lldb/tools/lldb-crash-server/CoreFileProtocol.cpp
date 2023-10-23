//===- CoreFileProtocol.cpp --------------------------------------*- C++ -*===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/Triple.h"
#include "lldb/API/SBThread.h"
#include "lldb/Utility/ArchSpec.h"
#include "Plugins/Process/Linux/NativeThreadLinux.h"

#include "CoreFileProtocol.h"
#include "CoreThreadProtocol.h"

using namespace lldb_private;
using namespace process_gdb_remote;
using namespace process_linux;

CoreFileProtocol::CoreFileProtocol(::pid_t pid,
                 NativeProcessProtocol::NativeDelegate &delegate,
                 const ArchSpec &arch,
                 MainLoop &mainloop, llvm::ArrayRef<::pid_t> tids,
                 lldb::crash_analyzer::CoreFile &corefile)
    : NativeProcessELF(pid, -1, delegate), m_arch(arch), m_main_loop(mainloop),
      m_corefile(corefile) {
  Status status;
  for (const auto &tid : tids) {
    AddThread(tid);
  }
  SetCurrentThreadID(tids[0]);
  SetState(lldb::StateType::eStateStopped, false);
}

Status CoreFileProtocol::ReadMemory(lldb::addr_t addr, void *buf, size_t size,
                                    size_t &bytes_read) {
  // Read memory from the core-file process.
  Status status;
  bytes_read = m_corefile.ReadMemory(addr, buf, size, status);
  if (bytes_read == size) {
    status.Clear();
  }
  return status;
}

llvm::Expected<std::unique_ptr<CoreFileProtocol>>
CoreFileProtocol::Factory::Read(lldb::crash_analyzer::CoreFile &corefile, 
                                NativeProcessProtocol::NativeDelegate &native_delegate,
                                MainLoop &mainloop) const {
    // Read the architecture from the core.
    std::string TargetTripleString = corefile.getTarget().GetTriple();
    llvm::Triple TheTriple(llvm::Triple::normalize(TargetTripleString));
    lldb_private::ArchSpec Arch(TheTriple.normalize());
    
    // Get the pid and the tids.
    auto process = corefile.getProcess();
    ::pid_t pid = process.GetProcessID();
    uint32_t numThreads = process.GetNumThreads();
    std::vector<::pid_t> tids;
    tids.reserve(numThreads);

    for (unsigned int i = 0; i < numThreads; i++) {
        lldb::SBThread thread = process.GetThreadAtIndex(i);
	tids.push_back(thread.GetThreadID());
    }

    return std::unique_ptr<CoreFileProtocol>(new CoreFileProtocol(
       pid, native_delegate, Arch, mainloop, tids, corefile));
}

void
CoreFileProtocol::AddThread(lldb::tid_t tid) {
    m_threads.push_back(std::make_unique<CoreThreadProtocol>(*this, tid,
                                                             m_corefile));
}
