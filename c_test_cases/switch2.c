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

char *foo = "hello";

void test_cf(char *arg, int val) {
switch(val) {
  case 1: printf("\n Good %c", *arg);
  break;
  case 0: 
    arg = (void *)0xdfdfddfdf; // first blame
    printf("\n Bad %c", *arg);
  break;
  default: ;
} 
 
}

int main() {

 char *good = foo;
 char *bad = (void *)0xabcdefffabcdefff; // second blame if we over-taint
 test_cf(good,1);
 test_cf(bad,0);

 return 0;
}
