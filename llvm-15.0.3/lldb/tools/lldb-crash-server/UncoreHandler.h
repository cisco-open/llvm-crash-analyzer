#include <cstdio>
#include <filesystem>
#include <memory>

#include "lldb/Host/FileSystem.h"
#include "llvm/ADT/SmallString.h"

#ifdef UNCORE_PATH

using namespace llvm;

namespace lldb {
class UncoreHandler {
  const std::string m_uncore_path = UNCORE_PATH;
  std::string m_working_dir;
  std::string m_uncore_json;

public:
  UncoreHandler(std::string uncore_json) {
    m_uncore_json = uncore_json;
    llvm::SmallString<64> cwd;
    if (std::error_code ec = llvm::sys::fs::current_path(cwd)) {
      llvm::errs() << "Error getting current directory: " << ec.message()
                   << "\n";
      exit(1);
    }
    m_working_dir = cwd.c_str();
  }

  bool RunUncore();
  ::pid_t RunLoaderProcess();
};
} // namespace lldb

#endif