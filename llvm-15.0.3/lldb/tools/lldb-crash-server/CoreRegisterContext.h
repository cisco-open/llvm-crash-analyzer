//===- CoreRegisterContext.h -------------------------------------*- C++ -*===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef COREREGISTERCONTEXT_H
#define COREREGISTERCONTEXT_H

#include "lldb/Host/common/NativeThreadProtocol.h"
#include "lldb/Host/common/NativeRegisterContext.h"

namespace lldb_private {

class CoreRegisterContext : public NativeRegisterContext {
public:
  CoreRegisterContext(NativeThreadProtocol &thread) : NativeRegisterContext(thread) {}
  ~CoreRegisterContext() {}
  uint32_t GetRegisterCount() const override { return 42; }
  uint32_t GetUserRegisterCount() const override { return 42; }
  const RegisterInfo *GetRegisterInfoAtIndex(uint32_t reg) const override { return NULL; }
  uint32_t GetRegisterSetCount() const override { return 42; }
  const RegisterSet *GetRegisterSet(uint32_t set_index) const override { return NULL; }
  Status ReadRegister(const RegisterInfo *reg_info, RegisterValue &reg_value) override { return Status(); }
  Status WriteRegister(const RegisterInfo *reg_info, const RegisterValue &reg_value) override { return Status(); }
  Status ReadAllRegisterValues(lldb::WritableDataBufferSP &data_sp) override { return Status(); }
  Status WriteAllRegisterValues(const lldb::DataBufferSP &data_sp) override { return Status(); }
};
} // namespace lldb_private
#endif
