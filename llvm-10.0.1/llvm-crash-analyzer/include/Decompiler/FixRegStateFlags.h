//===- FixRegStateFlags.h -------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Decompiler/Decompiler.h"
#include "llvm/CodeGen/MachineFunction.h"

namespace llvm {
namespace crash_analyzer {
class FixRegStateFlags {
public:
  FixRegStateFlags() = default;
  bool run(MachineFunction &MF);
};

} // end crash_analyzer namespace
} // end llvm namespace