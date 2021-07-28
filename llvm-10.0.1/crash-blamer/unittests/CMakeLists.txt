add_custom_target(CRASHBLAMERUnitTests)
set_target_properties(CRASHBLAMERUnitTests PROPERTIES FOLDER "CRASHBLAMERUnitTests Tests")
function(add_crash_balmer_unittest test_dirname)
  add_unittest(CRASHBLAMERUnitTests ${test_dirname} ${ARGN})
endfunction()

add_subdirectory(Analysis)
add_subdirectory(Decompiler)
