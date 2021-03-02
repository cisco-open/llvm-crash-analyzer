#include <stdio.h>

char *foo = "hello";

void test_cf(char *arg, int val) {
switch(val) {
  case 1: printf("\n Good %c", *arg);
  break;
  case 0: 
    arg = (void *)0xdfdfddfdf; // first blame
    printf("\n Bad %c", *arg);
  break;
  default: ;
} 
 
}

int main() {

 char *good = foo;
 char *bad = (void *)0xabcdefffabcdefff; // second blame if we over-taint
 test_cf(good,1);
 test_cf(bad,0);

 return 0;
}
