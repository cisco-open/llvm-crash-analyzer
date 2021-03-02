// null compare
#include <stdio.h>

int do_cmp(int *num) {
  int y = 8;
  if (y != 0)
    ++y;
  if (y == *num)
    --y;
  return y;
}

int main() {
  int *num = NULL;
  int res = do_cmp(num);
  return res;
}
