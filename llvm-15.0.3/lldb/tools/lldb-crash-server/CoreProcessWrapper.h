//===- CoreProcessWrapper.h --------------------------------------*- C++ -*===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef COREPROCESSWRAPPER_H
#define COREPROCESSWRAPPER_H

#include <memory>
#include <string>
#include <iostream>

#include "llvm/Support/ErrorOr.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/DataExtractor.h"
#include "lldb/API/SBProcess.h"
#include "lldb/Target/Process.h"

namespace lldb {

namespace crash_analyzer {

class CoreProcessWrapper : private SBProcess {

private:
  CoreProcessWrapper() { }

public:
  CoreProcessWrapper(const SBProcess &proc) :  SBProcess(proc) { }

  ~CoreProcessWrapper()  { }

  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> GetAuxvData() {
    auto proc_sp = GetSP();
    llvm::DataExtractor d = proc_sp->GetAuxvData().GetAsLLVM();
    llvm::StringRef auxv_str = d.getData();
    return llvm::MemoryBuffer::getMemBuffer(auxv_str, "auxv", false);
  }

};

} // namespace crash_analyzer

} // namespace lldb
#endif // COREPROCESSWRAPPER_H
