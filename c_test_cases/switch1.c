#include <stdio.h>

char *foo = "hello";

void test_cf(char *arg, int val) {
switch(val) {
  case 0: 
    printf("\n Bad %c", *arg);
  break;
  case 1: printf("\n Good %c", *arg);
  break;
  default: ;
} 
 
}

int main() {

 char *good = foo;
 char *bad = (void *)0xabcdefffabcdefff;
 test_cf(good,1);
 test_cf(bad,0);

 return 0;
}
