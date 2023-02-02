configure_lit_site_cfg(
  ${CMAKE_CURRENT_SOURCE_DIR}/lit.site.cfg.py.in
  ${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg.py
  MAIN_CONFIG
  ${CMAKE_CURRENT_SOURCE_DIR}/lit.cfg.py
)

configure_lit_site_cfg(
  ${CMAKE_CURRENT_SOURCE_DIR}/Unit/lit.site.cfg.py.in
  ${CMAKE_CURRENT_BINARY_DIR}/Unit/lit.site.cfg.py
  MAIN_CONFIG
  ${CMAKE_CURRENT_SOURCE_DIR}/Unit/lit.cfg.py
)

set(CRASH_ANALYZER_TEST_DEPENDS
  FileCheck
  llvm-crash-analyzer
  llvm-crash-analyzer-ta
  CRASHANALYZERUnitTests
  )
# Show progress bar!
list(APPEND LLVM_LIT_ARGS
    "-s"
)
add_lit_testsuite(check-llvm-crash-analyzer "Running the llvm-crash-analyzer regression tests"
  ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS ${CRASH_ANALYZER_TEST_DEPENDS}
  )
set_target_properties(check-llvm-crash-analyzer PROPERTIES FOLDER "Tests")
add_lit_testsuites(CRASH_ANALYZER ${CMAKE_CURRENT_SOURCE_DIR}
  DEPENDS ${CRASH_ANALYZER_TEST_DEPENDS}
)
