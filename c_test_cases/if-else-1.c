// Pointer arithmetic -- cannot find the blame

#include <stdio.h>

char *foo = "hello";

void test_cf(char *arg, int val1, int val2) {
switch(val1) {
  case 0: 
  case 1: 
   arg = arg + 3;
  if (val1) {
    while (val2--) {
	arg = 0;
    }
   }
   else {
    while (val2--) {
	arg=0;
    }
   }
    printf("\n Bad %c", *arg); // crash here bt #0
  break;
  case 2: printf("\n Good %c", *arg);
  break;
  default: ;
} 
 
}

int main() {
 char *good = foo;
 test_cf(good,1,1000); // bt #2
 return 0;
}
