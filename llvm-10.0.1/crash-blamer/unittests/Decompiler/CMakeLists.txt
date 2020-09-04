add_crash_balmer_unittest(CRASHBLAMERDecompilerTests
  Decompiler.cpp
)

target_link_libraries(CRASHBLAMERDecompilerTests
  PRIVATE CrashBlamerDecompiler)
