// Copyright 2014-2024 John Manferdelli, All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// or in the the file LICENSE-2.0.txt in the top level sourcedirectory
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
// File: test_kyber.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "kyber.h"

DEFINE_bool(print_all, false, "Print intermediate test computations");


bool test_kyber1() {
  return true;
}

bool test_kyber_support() {
  int a, b, c, r;

  a = 1;
  b = 2;
  r = round(a,b);
  if (FLAGS_print_all) {
    printf("a: %d, b: %d. round(a/b): %d\n", a, b, r);
  }
  if (r != 1) {
    printf("round fail(1)\n");
    return false;
  }

  a = 5;
  b = 4;
  r = round(a,b);
  if (FLAGS_print_all) {
    printf("a: %d, b: %d. round(a/b): %d\n", a, b, r);
  }
  if (r != 1) {
    printf("round fail(2)\n");
    return false;
  }

  a = 1;
  b = 4;
  r = round(a,b);
  if (FLAGS_print_all) {
    printf("a: %d, b: %d. round(a/b): %d\n", a, b, r);
  }
  if (r != 0) {
    printf("round fail(3)\n");
    return false;
  }

  int q, x, d;
  q = 3329;
  x =  5;
  d = 11;
  r = compress(q, x, d);
  if (FLAGS_print_all) {
    printf("q: %d, x: %d, d: %d. compress: %d\n", q, x, d, r);
  }
  if (r != 3) {
    printf("compress fail(1)\n");
    return false;
  }

  x = r;
  r = decompress(q, x, d);
  if (FLAGS_print_all) {
    printf("q: %d, x: %d, d: %d. decompress: %d\n", q, x, d, r);
  }
  if (r != 5) {
    printf("decompress fail(1)\n");
    return false;
  }

  return true;
}

TEST (support, test_kyber_support) {
  EXPECT_TRUE(test_kyber_support());
}
TEST (kyber, test_kyber_support) {
  EXPECT_TRUE(test_kyber_support());
}


int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (!init_crypto()) {
    printf("init_crypto failed\n");
    return 1;
  }

  int result = RUN_ALL_TESTS();

  close_crypto();
  printf("\n");
  return 0;
}
