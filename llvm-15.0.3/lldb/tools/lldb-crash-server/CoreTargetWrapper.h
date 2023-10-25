//===- CoreTargetWrapper.h --------------------------------------*- C++ -*===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef CORETARGETWRAPPER_H
#define CORETARGETWRAPPER_H

#include <memory>

#include "lldb/API/SBTarget.h"
#include "lldb/Target/Target.h"

using namespace lldb_private;

namespace lldb {

namespace crash_analyzer {

class CoreTargetWrapper : private SBTarget {
private:
  CoreTargetWrapper() { }

public:
  CoreTargetWrapper(SBTarget &target) : SBTarget(target) { }

  ~CoreTargetWrapper() { }

  size_t ReadMemory(lldb::addr_t addr, void *buf, size_t size, Status &status) {
    TargetSP target_sp = GetSP();
    Address a(addr);
    lldb::addr_t load_addr;

    return target_sp->ReadMemory(a, buf, size, status, true, &load_addr);
  }
};

} // namespace crash_analyzer

} // namespace lldb
#endif // CORETARGETWRAPPER_H
