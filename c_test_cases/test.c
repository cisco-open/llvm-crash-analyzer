void f3(int *ptr_param2) {
  *ptr_param2 = 0;
}
void f2(int *ptr_param) {
  int *ptr2;
  ptr2 = ptr_param;
  f3(ptr2);
}
int main()
{
  int *ptr;
  ptr = 0;
  f2(ptr);
  return 0;
}

