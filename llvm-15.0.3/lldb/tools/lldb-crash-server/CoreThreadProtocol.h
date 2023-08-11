//===- CoreThreadProtocol.h ---------------------------------------*- C++ -*===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef CORETHREADPROTOCOL_H
#define CORETHREADPROTOCOL_H

#include "lldb/Host/common/NativeProcessProtocol.h"
#include "CoreRegisterContext.h"

namespace lldb_private {

namespace process_gdb_remote {

  class CoreThreadProtocol : public NativeThreadProtocol {
  public:
    CoreThreadProtocol(NativeProcessProtocol &process, lldb::tid_t tid,
                       lldb::crash_analyzer::CoreFile &corefile)
       : NativeThreadProtocol(process, tid),
       m_reg_context_up(CoreRegisterContext::CreateCoreRegisterContext(
            process.GetArchitecture(), *this, corefile)) {}

    std::string GetName() override { return ""; }
    lldb::StateType GetState() override { return lldb::StateType::eStateStopped; }
    NativeRegisterContext &GetRegisterContext() override { return *m_reg_context_up; }
    bool GetStopReason(ThreadStopInfo &stop_info, std::string &description) override;
    Status SetWatchpoint(lldb::addr_t addr, size_t size, uint32_t watch_flags,
                         bool hardware) override { return Status(); }
    Status RemoveWatchpoint(lldb::addr_t addr)
                         override { return Status(); }
    Status SetHardwareBreakpoint(lldb::addr_t addr, size_t size) override
      { return Status(); }
                                
    Status RemoveHardwareBreakpoint(lldb::addr_t addr) override
      { return Status(); }

  private:
    std::unique_ptr<CoreRegisterContext> m_reg_context_up;
  };
} // process_gdb_remote
} // lldb_private
#endif
