//===-- GDBRemoteCommunicationServerCS.h ------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
#ifndef LLDB_TOOLS_LLDB_SERVER_GDBREMOTECOMMUNICATIONSERVERCS_H
#define LLDB_TOOLS_LLDB_SERVER_GDBREMOTECOMMUNICATIONSERVERCS_H

#include "Plugins/Process/gdb-remote/GDBRemoteCommunicationServerLLGS.h"
#include "CoreFile.h"
#include "CoreFileProtocol.h"

namespace lldb_private {

namespace process_gdb_remote {

class GDBRemoteCommunicationServerLLCS : public GDBRemoteCommunicationServerLLGS
{
public:
  GDBRemoteCommunicationServerLLCS(
    MainLoop &mainloop,
    const NativeProcessProtocol::Factory &process_factory) : 
  GDBRemoteCommunicationServerLLGS(mainloop, process_factory){
     RegisterPacketHandlers_LLCS();
  };

  Status ReadCoreFile(
    const std::string &core_file,
    const std::string sysroot,
    const std::string module_path,
    const std::string solib_path,
    llvm::ArrayRef<llvm::StringRef> Arguments
    );

  std::unique_ptr<lldb::crash_analyzer::CoreFile>& getCoreFile() {
    return m_corefile;
  }
  
  Status CreateProcessContext();

  void RegisterPacketHandlers_LLCS();

  PacketResult Handle_qC_LLCS(StringExtractorGDBRemote &packet);

  PacketResult Handle_qOffsets_LLCS(StringExtractorGDBRemote &packet);

protected:
private:
  std::unique_ptr<lldb::crash_analyzer::CoreFile> m_corefile;
  std::unique_ptr<CoreFileProtocol::Factory> m_corefile_factory;
  llvm::StringRef m_progname;
};

} // namespace process_gdb_remote
} // namespace lldb_private

#endif // LLDB_TOOLS_LLDB_SERVER_GDBREMOTECOMMUNICATIONSERVERCS_H
