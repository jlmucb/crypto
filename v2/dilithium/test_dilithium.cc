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
// File: test_dilithium.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "dilithium.h"

DEFINE_bool(print_all, false, "Print intermediate test computations");

bool test_module_arith() {
  int q = (1<<23) - (1<<13) + 1;
  int n = 3;

  coefficient_vector v1(q, n);
  coefficient_vector v2(q, n);
  coefficient_vector out1(q, n);
  coefficient_vector out2(q, n);

  // x^2 + x + 1
  v1.c_[0] = 1;
  v1.c_[1] = 1;
  v1.c_[2] = 1;

  //x^2 + (q-1)x + 2
  v2.c_[0] = 2;
  v2.c_[1] = q-1;
  v2.c_[2] = 1;

  if (!vector_add(v1, v2, &out1)) {
    printf("vector add fails\n");
    return false;
  }

  if (FLAGS_print_all) {
    print_coefficient_vector(v1);
    printf(" + ");
    print_coefficient_vector(v2);
    printf(" = ");
    print_coefficient_vector(out1);
    printf(" mod(%d)\n", v1.q_);
  }

  if (!vector_mult(v1, v2, &out2)) {
    printf("vector mult fails\n");
    return false;
  }


  if (FLAGS_print_all) {
    print_coefficient_vector(v1);
    printf(" * ");
    print_coefficient_vector(v2);
    printf(" = ");
    print_coefficient_vector(out2);
    printf(" mod(%d)\n", v1.q_);
  }

  if (out1.c_[2] != 2 || out1.c_[1] != 0 || out1.c_[0] != 3)
    return false;
  if (out2.c_[2] != 1 || out2.c_[1] != 1 || out2.c_[0] != 2)
    return false;

  return true;
}

bool test_dilithium1() {

  //dilithium_parameters params(int n, int k, int l, int q, int g_1, int g_2, int eta, int beta);

  if (FLAGS_print_all) {
  }

  return true;
}

TEST (dilithium, test_dilithium1) {
  EXPECT_TRUE(test_dilithium1());
}
TEST (module_arith, test_module_arith) {
  EXPECT_TRUE(test_module_arith());
}

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (!init_crypto()) {
    printf("init_crypto failed\n");
    return 1;
  }

  dilithium_parameters params;
  init_dilithium_parameters(&params);
  print_dilithium_parameters(params);

  int result = RUN_ALL_TESTS();

  close_crypto();
  printf("\n");
  return 0;
}
