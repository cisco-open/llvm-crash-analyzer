//===- CoreFile.h ------------------------------------------------*- C++ -*===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef CB_COREFILE_
#define CB_COREFILE_

#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSet.h"

#include <map>

using RegisterMap = std::map<const char*, const char*>;

namespace llvm {
namespace crash_blamer {

class CoreFile {
  const char *name;
  StringSet<> FunctionsFromBacktrace;
  RegisterMap GPRs;
public:
  CoreFile(StringRef name) : name(name.data()) { FunctionsFromBacktrace = {}; }

  void read(StringRef InputFile);
  StringSet<> &getFunctionsFromBacktrace() { return FunctionsFromBacktrace; }

  // Handle General Purpose Registers.
  RegisterMap &getGRPsFromCrashFrame() { return GPRs; }
  void insertIntoGPRFromCrashFrame(const char *reg, const char *value) {
    GPRs.insert(std::make_pair(reg, value));
  }
};

} // end crash_blamer namespace
} // end llvm namespace

#endif
