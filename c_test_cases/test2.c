// array
#include <stdio.h>

void fillbuffer( char *string, unsigned len) {
 int i = 0;
 for (i = 0; i < len; i++) {
   string[i] = 'A';
 }
}

int main() {
 char *str = NULL;
 fillbuffer(str, 16);
 return 0;
}


