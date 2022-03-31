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

// Pointer arithmetic -- cannot find the blame

#include <stdio.h>

char *foo = "hello";

void test_cf(char *arg, int val1, int val2) {
switch(val1) {
  case 0: 
  case 1: 
   arg = arg + 3;
  if (val1) {
    while (val2--) {
	arg = 0;
    }
   }
   else {
    while (val2--) {
	arg=0;
    }
   }
    printf("\n Bad %c", *arg); // crash here bt #0
  break;
  case 2: printf("\n Good %c", *arg);
  break;
  default: ;
} 
 
}

int main() {
 char *good = foo;
 test_cf(good,1,1000); // bt #2
 return 0;
}
