#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#ifndef __STDC__
#define const /**/
#endif

#define MAPSIZE (8 * 1024)

char *buf1;
char *buf2;
char *buf2ro;
char *buf3;

const unsigned char filler_ro[MAPSIZE] = {1, 2, 3, 4, 5, 6, 7, 8};

void mmapdata() {
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

char *get_buf2() {
  return buf2;
}

char *get_buf2ro() {
  return buf2ro;
}

char *get_buf3() {
  return buf3;
}
