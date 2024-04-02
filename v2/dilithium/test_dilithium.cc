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

  dilithium_parameters params;
  init_dilithium_parameters(&params);

  if (FLAGS_print_all) {
    print_dilithium_parameters(params);
  }

  return true;
}

bool test_dilithium1() {

  dilithium_parameters params;
  init_dilithium_parameters(&params);

  if (FLAGS_print_all) {
    print_dilithium_parameters(params);
  }

  module_array A(params.q_, 256, params.k_, params.l_);
  module_vector t(params.q_, params.l_, params.n_);
  module_vector s1(params.q_, params.k_, params.n_);
  module_vector s2(params.q_, params.l_, params.n_);
  
  printf("A.q_: %d, A.n_: %d, A.nr_: %d, A.nc_: %d\n",
      A.q_, A.n_, A.nr_, A.nc_);

  for (int r = 0; r < A.nr_; r++) {
    for (int c = 0; c < A.nc_; c++) {
      for (int k = 0; k < params.n_; k++) {
        unsigned t = 0;
        int l = crypto_get_random_bytes(4, (byte*)&t);
        t %= params.q_;
	if (A.c_[A.index(r, c)] == nullptr)
	  continue;
	coefficient_vector* vp = A.c_[A.index(r, c)];
	if (vp == nullptr)
	  continue;
        // printf("k: %d t: %d, r: %d, c: %d, index: %d\n", k, t, r, c, A.index(r, c));
	// printf("Size A.c_[A.index(r, c)].size %d\n", vp->c_.size());
        A.c_[A.index(r, c)]->c_[k] = t;
      }
    }
  }

  print_module_array(A);
  return true;

  if (!dilithium_keygen(params, &A, &t, &s1, &s2)) {
    printf("dilithium_keygen failed\n");
    return false;
  }

  int m_len = 3;
  byte M[3] = {0x1, 0x2, 0x3};

  module_vector z(params.q_, params.l_, params.n_);
  int len_c = 256;
  byte c[len_c];
  if (!dilithium_sign(params,  A, t, s1, s2, m_len, M, &z, len_c, c)) {
    printf("dilithium_sign failed\n");
    return false;
  }

  if (!dilithium_verify(params,  A,  t, s1, s2, m_len, M, z, len_c, c)) {
    printf("dilithium_verify failed\n");
    return false;
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
