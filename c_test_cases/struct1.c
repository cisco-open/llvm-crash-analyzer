// Retracer cannot find the blame
#include <stdio.h>
struct node {

int a;
char b;
int *c;
};

int foo(struct node *s) {
 return s->a+ *s->c; // crash here
}

int main() {

struct node n;
n.a = 10;
n.c = 0; // blame
int x = foo(&n);
printf("\n x = %d", x);
return 0;
}
