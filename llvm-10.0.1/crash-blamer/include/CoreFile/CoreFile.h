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

namespace llvm {
namespace crash_blamer {

class CoreFile {
  unsigned NumOfFrames = 0;
  const char *name;
  SmallVector<StringRef, 8> FunctionsFromBacktrace;
  FrameToRegsMap GPRs;
public:
  CoreFile(StringRef name) : name(name.data()) { FunctionsFromBacktrace = {}; }

  bool read(StringRef InputFile);
  SmallVector<StringRef, 8> &getFunctionsFromBacktrace() {
    return FunctionsFromBacktrace;
  }

  // Handle General Purpose Registers.
  FrameToRegsMap &getGRPsFromFrame() { return GPRs; }
  void insertIntoGPRsFromFrame(StringRef frame, std::vector<RegInfo> &Regs) {
    GPRs.insert(std::make_pair(frame, Regs));
  }

  void setNumOfFrames(unsigned frames) {
    NumOfFrames = frames;
  }
  unsigned getNumOfFrames() {
    return NumOfFrames;
  }
};

} // end crash_blamer namespace
} // end llvm namespace

#endif
