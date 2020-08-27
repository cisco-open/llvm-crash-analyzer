#include <stdio.h>

typedef struct {
  int *a;
  float b;
} T;

float f() {
  T p;
  p.a = NULL;
  g(&p);
  return p.b;
}

g(T *q) {
  int *t = q->a;
  h(t);
}

h(int *r) {
  *r = 0; // crash!!
}

main() {
  float val = f();
  printf("%f\n", val);
  return 0;
}
