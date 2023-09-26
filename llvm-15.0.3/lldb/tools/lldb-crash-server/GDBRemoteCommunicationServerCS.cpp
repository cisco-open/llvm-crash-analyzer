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
#if 0
  NativeThreadProtocol *thread = m_current_process->GetThreadAtIndex(0);
  if (!thread) {
    return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                   "No thread available.");
  }
  
  Log *log = GetLog(LLDBLog::Process | LLDBLog::Thread);

  NativeRegisterContext &reg_context = thread->GetRegisterContext();
#endif

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


#if 0
  response.Printf("<feature name=\"org.gnu.gdb.i386.core\">");

  const int register_count = reg_context.GetUserRegisterCount();
  for (int reg_index = 0; reg_index < register_count; reg_index++) {
    const RegisterInfo *reg_info = reg_context.GetRegisterInfoAtIndex(reg_index);
    if (!reg_info) {
      LLDB_LOGF(log, "%s failed to get register info at index %" PRIu32,
                "target.xml", reg_index);
      continue;
    }

    const char *reg_name = ((strcmp(reg_info->name, "rflags") == 0) ? "eflags" :
                           reg_info->name);
    response.Printf("<reg name=\"%s\" bitsize=\"%" PRIu32 "\" regnum=\"%d\" ",
                    reg_name, reg_info->byte_size * 8, reg_index);

    const char *register_set_name = 
        reg_context.GetRegisterSetNameForRegisterAtIndex(reg_index);
    if (register_set_name && strcmp(register_set_name,
                                    "Floating Point Registers") == 0) {
      response << "group=\"float\" ";
    }
    if (reg_info->byte_size == 10) {
      response.Printf("type=\"i387_ext\"/>");
    } else {
      response.Printf("type=\"int%d\"/>", reg_info->byte_size * 8);
    }
  }

  response << "<reg_name=\"k0\" bitsize=\"64\" type=\"uint64\" regnum=\"108\"/>";
  response.Printf("</feature>");
#endif

  response.Printf("</target>");

  return MemoryBuffer::getMemBufferCopy(response.GetString(), "target.xml");
}
