#include <stdio.h>

int do_xor(int *num) {
  int y = 8 ^ *num;
  return y;
}

int main() {
  int *num = NULL;
  int res = do_xor(num);
  return res;
}
