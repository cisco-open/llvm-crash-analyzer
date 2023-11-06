// RUN: %clang -g %s -o %t
// RUN: %gdb -q -x %S/vdso-warning-gc.gdb %t
// RUN: %python -c 'import socket; s = socket.socket(); s.bind(("", 0)); print(s.getsockname()[1])' > %t.port
// RUN: bash -c "%lldb-crash-server g --core-file %T/vdso-warning.core localhost:$(cat %t.port) %t > /dev/null 2>&1 &"
// RUN: sleep 1
// RUN: %gdb -q %t -batch -ex "target remote localhost:$(cat %t.port)" -ex "source %S/vdso-warning.gdb" 2>&1 | FileCheck %s

// CHECK-NOT: Could not load shared library symbols
// CHECK: main ()

// CHECK-NOT: No{{[[:space:]]*}}linux-vdso.so.1
// CHECK-NOT: No{{[[:space:]]*}}linux-gate.so.1


int main (void)
{
    return 0;
}
