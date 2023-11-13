// RUN: %clang -g %s -o %t
// RUN: %gdb -q %t -batch -ex "break abort_program" -ex "run" -ex "gcore ./Output/corefile.core"
// RUN: %python -c 'import socket; s = socket.socket(); s.bind(("", 0)); print(s.getsockname()[1])' > %t.port
// RUN: bash -c "%lldb-crash-server g --core-file %T/corefile.core localhost:$(cat %t.port) %t > /dev/null 2>&1 &"
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
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#ifndef __STDC__
#define	const	/**/
#endif

#define MAPSIZE (8 * 1024)

char *buf1;
char *buf2;
char *buf2ro;
char *buf3;

int coremaker_data = 1;	/* In Data section */
int coremaker_bss;	/* In BSS section */

const unsigned char filler_ro[MAPSIZE] = {1, 2, 3, 4, 5, 6, 7, 8};
const int coremaker_ro = 201;	/* In Read-Only Data section */

void abort_program () {
  abort();
}

void
mmapdata ()
{
  int j, fd;

  /* Allocate and initialize a buffer that will be used to write
     the file that is later mapped in. */

  buf1 = (char *) malloc (MAPSIZE);
  for (j = 0; j < MAPSIZE; ++j)
    {
      buf1[j] = j;
    }

  /* Write the file to map in */

  fd = open ("./Output/coremmap.data", O_CREAT | O_RDWR, 0666);
  if (fd == -1)
    {
      perror ("coremmap.data open failed");
      buf2 = (char *) -1;
      return;
    }
  write (fd, buf1, MAPSIZE);

  /* Now map the file into our address space as buf2 */

  buf2 = (char *) mmap (0, MAPSIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  if (buf2 == (char *) MAP_FAILED)
    {
      perror ("mmap failed");
      return;
    }

  /* Map in another copy, read-only.  We won't write to this copy so it
     will likely not end up in the core file.  */
  buf2ro = (char *) mmap (0, MAPSIZE, PROT_READ, MAP_PRIVATE, fd, 0);
  if (buf2ro == (char *) -1)
    {
      perror ("mmap failed");
      return;
    }

  /* Verify that the original data and the mapped data are identical.
     If not, we'd rather fail now than when trying to access the mapped
     data from the core file. */

  for (j = 0; j < MAPSIZE; ++j)
    {
      if (buf1[j] != buf2[j] || buf1[j] != buf2ro[j])
	{
	  fprintf (stderr, "mapped data is incorrect");
	  buf2 = buf2ro = (char *) -1;
	  return;
	}
    }
  /* Touch buf2 so kernel writes it out into 'core'. */
  buf2[0] = buf1[0];

  /* Create yet another region which is allocated, but not written to.  */
  buf3 = mmap (NULL, MAPSIZE, PROT_READ | PROT_WRITE,
               MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (buf3 == (char *) -1)
    {
      perror ("mmap failed");
      return;
    }
}

void
func2 ()
{
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

void
func1 ()
{
  func2 ();
}

int
main (int argc, char **argv)
{
  mmapdata ();
  func1 ();
  return 0;
}
