//===- CoreFileProtocol.h ----------------------------------------*- C++ -*===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_CRASH_SERVER_COREFILE_PROTOCOL_H
#define LLDB_CRASH_SERVER_COREFILE_PROTOCOL_H

#include "CoreFile.h"
#include "lldb/Host/common/NativeProcessProtocol.h"
#include "Plugins/Process/POSIX/NativeProcessELF.h"
#include "Plugins/Process/Utility/NativeProcessSoftwareSingleStep.h"

namespace lldb_private {

namespace process_gdb_remote {

class CoreFileProtocol : public NativeProcessELF {
public:
  Status Resume(const ResumeActionList &resume_actions)
                                override { return Status(); }

  Status Halt() override { return Status(); }

  Status Detach() override { return Status(); }

  Status Signal(int signo) override { return Status(); }

  Status Kill() override { return Status(); }

  Status ReadMemory(lldb::addr_t addr, void *buf, size_t size,
                    size_t &bytes_read) override;

  Status WriteMemory(lldb::addr_t addr, const void *buf, size_t size,
                     size_t &bytes_written) override { return Status(); }

  size_t UpdateThreads() override { return 0; }

  const ArchSpec &GetArchitecture() const override { return m_arch; }

  Status SetBreakpoint(lldb::addr_t addr, uint32_t size,
                       bool hardware) override {
    return Status();
  }

  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> GetAuxvData()
    const override { return make_error_code(llvm::errc::not_supported); }

  Status GetLoadedModuleFileSpec(const char *module_path,
                                 FileSpec &file_spec) override {
    return Status();
  }

  Status GetFileLoadAddress(const llvm::StringRef &file_name,
                            lldb::addr_t &load_addr) override {
    return Status();
  }

  class Factory {
  public:
    llvm::Expected<std::unique_ptr<CoreFileProtocol>>
    Read(lldb::crash_analyzer::CoreFile &corefile,
         NativeProcessProtocol::NativeDelegate &native_delegate,
         MainLoop &mainloop) const;

}; // CoreFileProtocol::Factory

private:
  ArchSpec m_arch;
  MainLoop &m_main_loop;
  lldb::crash_analyzer::CoreFile &m_corefile;

  CoreFileProtocol(::pid_t pid, NativeProcessProtocol::NativeDelegate &delegate,
                   const ArchSpec &arch, MainLoop &mainloop,
                   llvm::ArrayRef<::pid_t> tids,
                   lldb::crash_analyzer::CoreFile &corefile);
  void AddThread(lldb::tid_t tid);
}; // CoreFileProtocol

} // namespace process_gdb_remote
} // namespace lldb_private

#endif // LLDB_CRASH_SERVER_COREFILE_PROTOCOL_H 
