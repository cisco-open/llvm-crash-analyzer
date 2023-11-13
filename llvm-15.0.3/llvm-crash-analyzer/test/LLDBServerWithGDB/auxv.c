// RUN: %clang -g %s -o %t
// RUN: %gdb -q -x %S/auxv-gc.gdb %t
// RUN: %python -c 'import socket; s = socket.socket(); s.bind(("", 0)); print(s.getsockname()[1])' > %t.port
// RUN: bash -c "%lldb-crash-server g --core-file %T/auxv.core localhost:$(cat %t.port) %t > /dev/null 2>&1 &"
// RUN: sleep 1
// RUN: %gdb -q %t -batch -ex "target remote localhost:$(cat %t.port)" -ex "source %S/auxv.gdb" | sed -n '/ABORT/,/End of vector/p' > %T/gdb-with-lldb-output.txt
// RUN: %gdb -q -x %S/auxv.gdb %t %T/auxv.core | sed -n '/ABORT/,/End of vector/p' > %T/gdb-direct-output.txt
// RUN: diff -s %T/gdb-with-lldb-output.txt %T/gdb-direct-output.txt | FileCheck %s

// CHECK: are identical
// CHECK-NOT: <
// CHECK-NOT: >
// CHECK-NOT: ---

#ifndef __STDC__
#define	const	/**/
#endif

#ifndef HAVE_ABORT
#define HAVE_ABORT 1
#endif

#if HAVE_ABORT
#include <stdlib.h>
#define ABORT abort()
#else
#define ABORT {char *invalid = 0; *invalid = 0xFF;}
#endif

#ifdef USE_RLIMIT
# include <sys/resource.h>
# ifndef RLIM_INFINITY
#  define RLIM_INFINITY -1
# endif
#endif /* USE_RLIMIT */

/* Don't make these automatic vars or we will have to walk back up the
   stack to access them. */

char *buf1;
char *buf2;

int coremaker_data = 1;	/* In Data section */
int coremaker_bss;	/* In BSS section */

const int coremaker_ro = 201;	/* In Read-Only Data section */

void
func2 (int x)
{
  int coremaker_local[5];
  int i;
  static int y;

#ifdef USE_RLIMIT
  {
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };

    setrlimit (RLIMIT_CORE, &rlim);
  }
#endif

  /* Make sure that coremaker_local doesn't get optimized away. */
  for (i = 0; i < 5; i++)
    coremaker_local[i] = i;
  coremaker_bss = 0;
  for (i = 0; i < 5; i++)
    coremaker_bss += coremaker_local[i];
  coremaker_data = coremaker_ro + 1;
  y = 10 * x;
  ABORT;
}

void
func1 (int x)
{
  func2 (x * 2);
}

int main ()
{
  func1 (10);
  return 0;
}