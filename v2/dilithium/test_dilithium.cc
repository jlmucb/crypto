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

bool test_arith_support() {

  // inf_norm
  vector<int> v;
  for (int i = 0; i < 20; i++)
    v.push_back(10 * i);
  int n = inf_norm(v);
  if (FLAGS_print_all) {
    printf("v: ");
    for(int i = 0; i < (int)v.size(); i++)
      printf(" %3d", v[i]);
    printf("\n");
    printf("inf norm: %d\n", n);
  }
  if (n != 190)
   return false;

  // high_bits
  int x = 0xfefefe;
  int a = 0x8ff;
  int h =high_bits(x, a);
  if (FLAGS_print_all) {
    printf("x: %08x %d, a: %08x %d, h: %08x %d\n", x, x, a, a, h, h);
  }
  if (h != 3628)
    return false;

  // low_bits
  int  l = low_bits(x, a);
  if (FLAGS_print_all) {
    printf("x: %08x %d, a: %08x %d, l: %08x %d\n", x, x, a, a, l, l);
  }
  if (l != 854)
    return false;

  // H 
  // SHAKE128("abc") = 0x5881092dd818bf5cf8a3ddb793fbcba7
  // SHAKE256("abc") = 0x483366601360a8771c6863080cc4114d
  byte in[4] = {
	  (byte)'a', (byte)'b', (byte)'c', 0xf0
  };
  int out_len = 32;
  byte out[32];
  memset(out, 0, 32);
  if (!H(3, in, &out_len, out))
    return false;
  if (FLAGS_print_all) {
    printf("\nin : ");
    print_bytes(3, in);
    //printf("\n");
    printf("out: ");
    print_bytes(32, out);
    printf("\n");
  }

  return true;
}

bool test_coefficient_arith() {
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

bool test_module_arith() {
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
TEST (coefficient_arith, test_coefficient_arith) {
  EXPECT_TRUE(test_coefficient_arith());
}
TEST (arith_support, test_arith_support) {
  EXPECT_TRUE(test_arith_support());
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
