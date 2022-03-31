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
typedef struct node {
  int *fn; 
} T;

void h(int *r) {
  *r = 3; // crash
}

void g (T*q) {
  int *t = q->fn;
  h(t);
}

void f() {
  T p;
  T q2;
  p.fn = NULL; // blame point
  q2.fn = NULL;
  g(&p);
}

int main() {
 f();
 return 0;
}
