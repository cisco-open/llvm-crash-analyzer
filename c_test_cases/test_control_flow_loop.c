#include <stdlib.h>

int f2(char *input) { return crasher(input, 1); }
int crasher(char *input, int crash) {
  if (crash)
    input = NULL;
  input[0] = '1';
  input[1] = '2';
  input[2] = '3';
  input[3] = '\0';
  f2(input);
  if (crash)
    return 0;
  else
    return 1;
}

int f1() {
  char *input = (char *)malloc(sizeof(char) * 10);
  return crasher(input, 1);
}
int main(int argc, char **argv) {
  f1();
  return 0;
}
