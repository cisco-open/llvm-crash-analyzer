//===- Decompiler.cpp ------------ Unit test-------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Decompiler/Decompiler.h"
#include "gtest/gtest.h"

namespace {
  TEST(Decompiler, add) {
    ASSERT_TRUE(1 == 1);
    EXPECT_TRUE(0);
  }
}
