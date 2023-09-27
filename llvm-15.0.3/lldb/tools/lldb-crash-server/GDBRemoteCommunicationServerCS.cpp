//===-- GDBRemoteCommunicationServerCS.cpp --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Utility/LLDBLog.h"
#include "lldb/Host/common/NativeRegisterContext.h"
#include "GDBRemoteCommunicationServerCS.h"
#include "CoreFileProtocol.h"

using namespace lldb_private;

using namespace lldb_private::process_gdb_remote;

using namespace llvm;

Status GDBRemoteCommunicationServerLLCS::ReadCoreFile(
  const std::string &core_file,
  const std::string sysroot,
  const std::string module_path,
  const std::string solib_path,
  llvm::ArrayRef<llvm::StringRef> Arguments
  )
{
    Status error;
    m_progname = Arguments[0];
    llvm::StringRef solib_search_path(solib_path);

    m_corefile = std::make_unique<lldb::crash_analyzer::CoreFile>(core_file,
                                                                m_progname,
       	                                                        sysroot,
                                                                module_path);
    if (!m_corefile || !m_corefile->read(solib_search_path)) {
        error.SetErrorString("Unable to read the core file.");
	return error;
    }

    return CreateProcessContext();
}

Status
GDBRemoteCommunicationServerLLCS::CreateProcessContext() {
    m_corefile_factory = std::make_unique<CoreFileProtocol::Factory>();
    auto corefile_or = m_corefile_factory->Read(*m_corefile, *this, m_mainloop);
    if (!corefile_or) {
      Status error(corefile_or.takeError());
      llvm::errs() << llvm::formatv("Failed to load corefile.\n");
      return error;
    }
    m_current_process = m_continue_process = corefile_or->get();
    m_debugged_processes.emplace(m_current_process->GetID(),
        DebuggedProcess{std::move(*corefile_or), DebuggedProcess::Flag{}});
    return Status();
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServerLLCS::Handle_qC_LLCS(StringExtractorGDBRemote &packet) {
  SendStopReasonForState(*m_current_process, m_current_process->GetState(),
                         false); /* TODO: Handle the return value of Handle_qC() */
  return Handle_qC(packet);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServerLLCS::Handle_qOffsets_LLCS(StringExtractorGDBRemote &packet) {
  StreamString response;
  response.PutCString(""); /* Dummy data. */
  return SendPacketNoLock(response.GetString());
}

void
GDBRemoteCommunicationServerLLCS::RegisterPacketHandlers_LLCS() {
  RegisterMemberFunctionHandler(
      StringExtractorGDBRemote::eServerPacketType_qC,
      &GDBRemoteCommunicationServerLLCS::Handle_qC_LLCS);
  RegisterMemberFunctionHandler(
      StringExtractorGDBRemote::eServerPacketType_qOffsets,
      &GDBRemoteCommunicationServerLLCS::Handle_qOffsets_LLCS);
}

llvm::Expected<std::unique_ptr<llvm::MemoryBuffer>>
GDBRemoteCommunicationServerLLCS::BuildTargetXml() {
  StreamString response;
  auto archString = m_current_process->GetArchitecture().GetTriple().
                                       getArchName().str();

  response.Printf("<?xml version=\"1.0\"?>");
  response.Printf("<target version=\"1.0\">");

  response.Printf("<architecture>");
  if (archString == "x86_64") {
    response.Printf("i386:x86-64");
  }
  response.Printf("</architecture>");

  response.Printf("</target>");

  return MemoryBuffer::getMemBufferCopy(response.GetString(), "target.xml");
}
