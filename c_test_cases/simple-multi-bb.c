// Got from: https://github.com/djolertrk/the-tests/blob/main/C/crashes/multi-bb.c

int fn(int *ptr) {
  int x = 8;
  if (x < 9)
    ++x;
  else if (x > 11)
    --x;
  else {
    --x;
    ++x;
  }

  x = *ptr + x;

  return x;
}

int main()
{
  int y = 0x4;
  int res = fn(y);
  return 0;
}

