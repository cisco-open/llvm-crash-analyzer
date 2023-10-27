break main
set environment LD_DEBUG=unused
run
gcore ./Output/vdso-warning.core
quit