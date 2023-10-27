// RUN: %clang -g %s -o %t
// RUN: %gdb -q -x %S/vdso-warning-gc.gdb %t
// RUN: bash -c "%lldb-crash-server g --core-file %T/vdso-warning.core localhost:1234 %t > /dev/null 2>&1 &"
// RUN: sleep 1
// RUN: %gdb -q -x %S/vdso-warning.gdb %t 2>&1 | FileCheck %s

// CHECK-NOT: Could not load shared library symbols
// CHECK: main ()

// CHECK-NOT: No{{[[:space:]]*}}linux-vdso.so.1
// CHECK-NOT: No{{[[:space:]]*}}linux-gate.so.1


int main (void)
{
    return 0;
}
