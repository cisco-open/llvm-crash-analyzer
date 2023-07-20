//===-- GDBRemoteCommunicationServerCS.cpp --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "GDBRemoteCommunicationServerCS.h"

using namespace lldb_private;
using namespace lldb_private::process_gdb_remote;

Status GDBRemoteCommunicationServerLLCS::ReadCoreFile(
  const std::string &core_file,
  const std::string sysroot,
  const std::string module_path,
  const std::string solib_path,
  llvm::ArrayRef<llvm::StringRef> Arguments
  )
{
    Status error;
    llvm::StringRef progname = Arguments[0];
    llvm::StringRef solib_search_path(solib_path);

    corefile = std::make_unique<lldb::crash_analyzer::CoreFile>(core_file,
                                                                progname,
       	                                                        sysroot,
                                                                module_path);
    if (!corefile->read(solib_search_path)) {
        error.SetErrorString("Unable to read the core file.");
    }
    return error;
}
