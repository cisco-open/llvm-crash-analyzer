add_custom_target(CRASHANALYZERUnitTests)
set_target_properties(CRASHANALYZERUnitTests PROPERTIES FOLDER "CRASHANALYZERUnitTests Tests")
function(add_crash_balmer_unittest test_dirname)
  add_unittest(CRASHANALYZERUnitTests ${test_dirname} ${ARGN})
endfunction()

add_subdirectory(Analysis)
add_subdirectory(Decompiler)
