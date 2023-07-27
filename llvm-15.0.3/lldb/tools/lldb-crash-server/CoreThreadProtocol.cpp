//===- CoreThreadProtocol.cpp -------------------------------------*- C++ -*===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "CoreThreadProtocol.h"
#include <csignal>

using namespace lldb_private;
using namespace lldb_private::process_gdb_remote;

bool
CoreThreadProtocol::GetStopReason(ThreadStopInfo &stop_info,
                                  std::string &description) {
  description = "signal";

  stop_info.reason = lldb::StopReason::eStopReasonSignal;
  stop_info.signo = SIGSEGV;
  return true;
}

