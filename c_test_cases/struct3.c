#include <stdio.h>
#include <stdlib.h>

struct node {
int a;
char b;
int *c;
};

int foo(int *s) {
 printf("\n x = %d", *s); // crash here
 return *s *2;
}

int main() {

struct node n;
int x = 9;
n.a = 10;
n.c= NULL;
int d = foo(n.c);
printf("\n d = %d", d);
return 0;
}
