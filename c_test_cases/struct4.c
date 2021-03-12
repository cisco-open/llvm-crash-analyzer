#include <stdio.h>
#include <stdlib.h>

struct node {
int a;
char *b;
int *c;
};

struct node *n;

void foo(struct node *s) {
 printf("\n %s %d", s->b, *s->c);
}

int main() {
  n = malloc(2);
  foo(n);
  return 0;
}
