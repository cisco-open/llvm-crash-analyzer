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

::pid_t lldb::UncoreHandler::RunLoaderProcess() {

  ::pid_t pid = fork();

  if (pid == -1) {
    llvm::errs() << "Failed to fork loader.bin process. \n";
    return LLDB_INVALID_PROCESS_ID;
  } else if (pid == 0) {
    std::string str1 = m_working_dir + "/outdir/loader.bin";
    std::string str2 = m_working_dir + "/outdir/core.ctx";

    dup2(STDOUT_FILENO, 1);
    dup2(STDERR_FILENO, 2);

    execlp(str1.c_str(), "loader.bin", str2.c_str(), "loop", nullptr);

    llvm::errs() << "Failed to execute loader.bin process. \n";
  } else {
    sleep(2);
    return pid;
  }

  return LLDB_INVALID_PROCESS_ID;
}
