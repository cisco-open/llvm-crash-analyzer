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
