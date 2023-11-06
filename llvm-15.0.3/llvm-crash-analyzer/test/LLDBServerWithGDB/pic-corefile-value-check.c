// RUN: %clang -g -fPIC -shared -o %T/libpic.so %S/Input/pic-lib.c
// RUN: %clang -g -o %t %s -L%T -lpic -Wl,-rpath,'%T'
// RUN: %gdb -q %t -batch -ex "break abort_program" -ex "run" -ex "gcore ./Output/pic-corefile-value-check.core"
// RUN: %python -c 'import socket; s = socket.socket(); s.bind(("", 0)); print(s.getsockname()[1])' > %t.port
// RUN: bash -c "%lldb-crash-server g --core-file %T/pic-corefile-value-check.core localhost:$(cat %t.port) %t > /dev/null 2>&1 &"
// RUN: sleep 1
// RUN: %gdb -q %t -batch -ex "target remote localhost:$(cat %t.port)" -ex "source %S/corefile.gdb" 2>&1 | FileCheck %s

// CHECK: $1 = 202
// CHECK: $2 = 10
// CHECK: $3 = 201
// CHECK: $4 = {0, 1, 2, 3, 4}

// CHECK: #0  abort_program ()
// CHECK: #1  0x{{[0-9a-f]+}} in func2 ()
// CHECK: #2  0x{{[0-9a-f]+}} in func1 ()
// CHECK: #3  0x{{[0-9a-f]+}} in main

// CHECK: rax {{0x[0-9a-f]+}} 
// CHECK-NEXT: rbx {{0x[0-9a-f]+}} 
// CHECK-NEXT: rcx {{0x[0-9a-f]+}} 
// CHECK-NEXT: rdx {{0x[0-9a-f]+}} 
// CHECK-NEXT: rsi {{0x[0-9a-f]+}} 
// CHECK-NEXT: rdi {{0x[0-9a-f]+}} 
// CHECK-NEXT: rbp {{0x[0-9a-f]+}} 
// CHECK-NEXT: rsp {{0x[0-9a-f]+}} 
// CHECK-NEXT: r8 {{0x[0-9a-f]+}} 
// CHECK-NEXT: r9 {{0x[0-9a-f]+}} 
// CHECK-NEXT: r10 {{0x[0-9a-f]+}} 
// CHECK-NEXT: r11 {{0x[0-9a-f]+}} 
// CHECK-NEXT: r12 {{0x[0-9a-f]+}} 
// CHECK-NEXT: r13 {{0x[0-9a-f]+}} 
// CHECK-NEXT: r14 {{0x[0-9a-f]+}} 
// CHECK-NEXT: r15 {{0x[0-9a-f]+}} 
// CHECK-NEXT: rip {{0x[0-9a-f]+}} 
// CHECK-NEXT: eflags {{0x[0-9a-f]+}}
// CHECK-NEXT: cs {{0x[0-9a-f]+}}
// CHECK-NEXT: ss {{0x[0-9a-f]+}}
// CHECK-NEXT: ds {{0x[0-9a-f]+}}
// CHECK-NEXT: es {{0x[0-9a-f]+}}
// CHECK-NEXT: fs {{0x[0-9a-f]+}}
// CHECK-NEXT: gs {{0x[0-9a-f]+}}

// CHECK: 0x{{[0-9a-f]+}}:	0	1	2	3	4	5	6	7
// CHECK: 0x{{[0-9a-f]+}}:	0	1	2	3	4	5	6	7

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

extern void mmapdata();
extern char *get_buf2();
extern char *get_buf2ro();
extern char *get_buf3();

int coremaker_data = 1; /* In Data section */
int coremaker_bss;      /* In BSS section */
const int coremaker_ro = 201; /* In Read-Only Data section */

void abort_program() {
  abort();
}

void func2() {
  int coremaker_local[5];
  int i;

#ifdef SA_FULLDUMP
  /* Force a corefile that includes the data section for AIX.  */
  {
    struct sigaction sa;

    sigaction (SIGABRT, (struct sigaction *)0, &sa);
    sa.sa_flags |= SA_FULLDUMP;
    sigaction (SIGABRT, &sa, (struct sigaction *)0);
  }
#endif

  /* Make sure that coremaker_local doesn't get optimized away. */
  for (i = 0; i < 5; i++)
    coremaker_local[i] = i;
  coremaker_bss = 0;
  for (i = 0; i < 5; i++)
    coremaker_bss += coremaker_local[i];
  coremaker_data = coremaker_ro + 1;
  abort_program ();
}

void func1() {
  func2();
}

int main(int argc, char **argv) {
  mmapdata ();
  func1 ();
  return 0;
}
