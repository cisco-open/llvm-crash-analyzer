//===- CoreRegisterContext_x86_64.h ------------------------------*- C++ -*===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef COREREGISTERCONTEXT_X86_64_H
#define COREREGISTERCONTEXT_X86_64_H

#include <iostream>

#include "Plugins/Process/Linux/NativeRegisterContextLinux_x86_64.h"

#include "CoreThreadProtocol.h"

namespace lldb_private {

namespace process_gdb_remote {

class CoreRegisterContext_x86_64 : public CoreRegisterContext,
          virtual public process_linux::NativeRegisterContextLinux_x86_64 {
public:
  CoreRegisterContext_x86_64(const ArchSpec &target_arch,
                             CoreThreadProtocol &thread,
                             lldb::crash_analyzer::CoreFile &corefile);

  Status DoReadRegisterValue(uint32_t offset, const char *reg_name,
                             uint32_t size, RegisterValue &value) override;

  Status DoWriteRegisterValue(uint32_t offset, const char *reg_name,
                              const RegisterValue &value) override {
    std::cout << "unsupported." << std::endl;
    return Status();
  }

  uint32_t GetRegisterCount() const override {
    return NativeRegisterContextLinux_x86_64::GetRegisterCount();
  }

  uint32_t GetUserRegisterCount() const override {
    return NativeRegisterContextLinux_x86_64::GetUserRegisterCount();
  }

  uint32_t GetRegisterSetCount() const override {
    return NativeRegisterContextLinux_x86_64::GetRegisterSetCount();
  }

  const RegisterSet *GetRegisterSet(uint32_t set_index) const override {
    return NativeRegisterContextLinux_x86_64::GetRegisterSet(set_index);
  }

  const RegisterInfo *GetRegisterInfoAtIndex(uint32_t reg) const override {
    return NativeRegisterContextLinux_x86_64::GetRegisterInfoAtIndex(reg);
  }

  Status ReadRegister(const RegisterInfo *reg_info, RegisterValue &reg_value)
                                   override {
    return NativeRegisterContextLinux_x86_64::ReadRegister(reg_info, reg_value);
  }

private:
  lldb::crash_analyzer::CoreFile &m_corefile;
};

} // namespace process_gdb_remote

} // namespace lldb_private
#endif // COREREGISTERCONTEXTLINUX_H
