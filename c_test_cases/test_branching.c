/*
 * Copyright 2022 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
int f1(int);
int f2(char *, int *);
int f3(char *, int *);
int f4(char *, int *);

int f1(int choice) {
  char *a = malloc(sizeof(char) * 50);
  int *b = malloc(sizeof(int));
  *b = 10;
  if (choice)
    f2(a, b);
  else
    f3(a, b);
  free(a);
  free(b);
  b = 0;
  return 0;
}

int f2(char *a, int *b) {
  sprintf(a, "f2\n");
  *b = 2;
  f4(a, b);
  return 0;
}
int f3(char *a, int *b) {
  sprintf(a, "f3\n");
  *b = 3;
  f4(a, b);
  return 0;
}

int f4(char *a, int *b) {
  sprintf(a, "f4\n");
  //   b = 0;
  *b = 4;
  return 0;
}

int main(int argc, char **argv) {
  int choice = 0;
  if (argc > 1) {
    choice = atoi(argv[1]);
  }
  f1(choice);

  return 0;
}
