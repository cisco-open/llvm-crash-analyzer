//===- CoreRegisterContext_x86_64.cpp ------------------------------*- C++ -*===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Plugins/Process/Utility/RegisterInfoInterface.h"
#include "Plugins/Process/Utility/RegisterContextLinux_x86_64.h"
#include "lldb/Utility/RegisterValue.h"

#include "CoreRegisterContext_x86_64.h"
#include "CoreFile.h"

using namespace lldb_private;

using namespace lldb_private::process_gdb_remote;

std::unique_ptr<CoreRegisterContext>
CoreRegisterContext::CreateCoreRegisterContext(const ArchSpec &arch,
                                   CoreThreadProtocol &thread,
                                   lldb::crash_analyzer::CoreFile &corefile) {
  return std::unique_ptr<CoreRegisterContext_x86_64>(
      new CoreRegisterContext_x86_64(arch, thread, corefile));
}

static RegisterInfoInterface *
CreateCoreRegisterInfoInterface(const ArchSpec &target_arch) {
    return new RegisterContextLinux_x86_64(target_arch);
}

CoreRegisterContext_x86_64::CoreRegisterContext_x86_64(
                             const ArchSpec &target_arch,
                             CoreThreadProtocol &thread,
                             lldb::crash_analyzer::CoreFile &corefile)
  : NativeRegisterContextRegisterInfo(
      thread, CreateCoreRegisterInfoInterface(target_arch)),
  NativeRegisterContextLinux_x86_64(target_arch, thread),
  CoreRegisterContext(thread),
  m_corefile(corefile) {}

Status
CoreRegisterContext_x86_64::DoReadRegisterValue(uint32_t offset,
                                                const char *reg_name,
                                                uint32_t size,
                                                RegisterValue &value) {
  lldb::tid_t tid = CoreRegisterContext::m_thread.GetID();
  auto functions = m_corefile.getFunctionsFromBacktrace(tid);
  auto currentFrameName = functions[0];
  FrameToRegsMap regmap = m_corefile.getGPRsFromFrame(tid);
  auto reginfo = regmap.find(currentFrameName)->second;

  for (auto Reg : reginfo) {
    const char *rName = Reg.regName.c_str();
    if (::strcmp(rName, reg_name) == 0) {
      unsigned long regValue = stoul(Reg.regValue, 0, 16);
      value.SetUInt(regValue, size);
      break;
    }
  }
  return Status();
}
