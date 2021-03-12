#include <stdio.h>

void foo(int *a, int n) {
printf("\n val = %d", a[n]); 
}

int main() {
int arr[2];
int *ptr = &arr[0];
foo(ptr,5000);
return 0;
}
