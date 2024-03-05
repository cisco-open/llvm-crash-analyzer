#include <cstdio>
#include <iostream>
#include <memory>
#include <regex>
#include <fstream>
#include <unistd.h>
#include <fcntl.h>

#include "UncoreHandler.h"

using namespace llvm;
using namespace lldb;

bool lldb::UncoreHandler::RunUncore() {
  std::string cmd =
      m_uncore_path + " -c " + m_uncore_json + " > /dev/null 2>&1";

  int status = std::system(cmd.c_str());

  std::string loader_file_path = m_working_dir + "/outdir/loader.bin";

  if (status != 0 && !llvm::sys::fs::exists(loader_file_path)) {
    llvm::errs() << "Uncore execution failed.\n";
    return false;
  }

  return true;
}

bool WriteToPipe(std::string working_dir) {
  std::string pipe_path = working_dir + "/gdb_lldb_signal_pipe";
  int fd = open(pipe_path.c_str(), O_WRONLY);
  if (fd == -1) {
    llvm::errs() << "Failed to open the FIFO pipe. \n";
    return false;
  }

  std::string message = "Crash server is ready.";
  if (write(fd, message.c_str(), message.size()) == -1) {
    llvm::errs() << "Failed to write into the pipe. \n";
    close(fd);
    return false;
  }

  close(fd);
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
    // TODO: Some kind of synchronization should be implemented with loader.bin
    // so this can be removed
    sleep(20);

    if (!WriteToPipe(m_working_dir)) {
      return LLDB_INVALID_PROCESS_ID;
    }

    return pid;
  }

  return LLDB_INVALID_PROCESS_ID;
}
