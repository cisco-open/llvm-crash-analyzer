#include <cstdio>
#include <iostream>
#include <memory>
#include <regex>

#include "UncoreHandler.h"

using namespace llvm;
using namespace lldb;

bool lldb::UncoreHandler::RunUncore() {
  std::string cmd =
      m_uncore_path + " -c " + m_uncore_json + " > /dev/null 2>&1";

  int status = std::system(cmd.c_str());

  if (status != 0) {
    llvm::errs() << "Uncore execution failed.\n";
    return false;
  }

  return true;
}

// TODO handle killing loader.bin in case of unexpected termination
std::pair<::pid_t, std::string> lldb::UncoreHandler::RunLoaderProcess() {
  std::string cmd = m_working_dir + "/outdir/loader.bin " + m_working_dir +
                    "/outdir/core.ctx loop &";

  m_pipe.reset(popen(cmd.c_str(), "r"));

  if (!m_pipe) {
    llvm::errs() << "Failed to run laoder.bin. \n";
    return std::make_pair(LLDB_INVALID_PROCESS_ID, "");
  }

  std::string line, result = "";
  char ch;

  while (fread(&ch, 1, 1, m_pipe.get())) {
    line += ch;
    if (ch == '\n') {
      if (line.find(" continue") != std::string::npos)
        break;
      result += line;
      line.clear();
    }
  }

  std::regex attach_regex("attach (0x[0-9a-fA-F]+)");
  std::regex set_regex("\\(gdb\\) set \\*\\(\\(int\\*\\).*");
  std::smatch matches;

  ::pid_t pid = LLDB_INVALID_PROCESS_ID;
  std::string set_cmd;

  if (std::regex_search(result, matches, attach_regex) && matches.size() > 1) {
    std::string pid_str = matches[1];
    unsigned long long_pid = strtoul(pid_str.c_str(), nullptr, 16);
    pid = static_cast<::pid_t>(long_pid);
  }

  if (std::regex_search(result, matches, set_regex) && matches.size() > 0) {
    set_cmd = matches[0];
  }

  return std::make_pair(pid, set_cmd);
}