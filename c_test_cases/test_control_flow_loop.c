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

#include <stdlib.h>

int f2(char *input) { return crasher(input, 1); }
int crasher(char *input, int crash) {
  if (crash)
    input = NULL;
  input[0] = '1';
  input[1] = '2';
  input[2] = '3';
  input[3] = '\0';
  f2(input);
  if (crash)
    return 0;
  else
    return 1;
}

int f1() {
  char *input = (char *)malloc(sizeof(char) * 10);
  return crasher(input, 1);
}
int main(int argc, char **argv) {
  f1();
  return 0;
}
