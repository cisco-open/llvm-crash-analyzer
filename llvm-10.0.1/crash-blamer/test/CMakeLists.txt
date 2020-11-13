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

set(CRASH_BLAMER_TEST_DEPENDS
  FileCheck
  crash-blamer
  crash-blamer-ta
  CRASHBLAMERUnitTests
  )
# Show progress bar!
list(APPEND LLVM_LIT_ARGS
    "-s"
)
add_lit_testsuite(check-crash-blamer "Running the crash-blamer regression tests"
  ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS ${CRASH_BLAMER_TEST_DEPENDS}
  )
set_target_properties(check-crash-blamer PROPERTIES FOLDER "Tests")
add_lit_testsuites(CRASH_BLAMER ${CMAKE_CURRENT_SOURCE_DIR}
  DEPENDS ${CRASH_BLAMER_TEST_DEPENDS}
)
