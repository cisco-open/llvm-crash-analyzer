// Retracer cannot find the blame
// concrete mem address may find the correct blame line
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
n.c = 0; // blame
n.a = 10;
int x = foo(&n);
printf("\n x = %d", x);
return 0;
}
