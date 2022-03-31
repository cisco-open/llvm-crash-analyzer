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

