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
  coefficient_vector out2(q, 2 * n);

  // x^2 + x + 1
  v1.c_[0] = 1;
  v1.c_[1] = 1;
  v1.c_[2] = 1;

  //x^2 + (q-1)x + 2
  v2.c_[0] = 2;
  v2.c_[1] = q-1;
  v2.c_[2] = 1;

  coefficient_vector_zero(&out1);
  if (!coefficient_add(v1, v2, &out1)) {
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

  coefficient_vector_zero(&out2);
  if (!coefficient_mult(v1, v2, &out2)) {
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

  if (coefficient_equal(v1, v2)) {
    printf("coefficient_equal fails\n");
    return false;
  }

  if (out1.c_[2] != 2 || out1.c_[1] != 0 || out1.c_[0] != 3) {
    printf("coefficient comparison fail 1\n");
    return false;
  }
  if (out2.c_[2] != 2 || out2.c_[1] != 0 || out2.c_[0] != 2) {
    printf("coefficient comparison fail 2\n");
    return false;
  }

  if (!coefficient_set_vector(out1, &out2)) {
    printf("coefficient_set_vector failed\n");
    return false;
  }
  if (!coefficient_equal(out1, out2)) {
    printf("out 1 != out2\n");
    return false;
  }

  if (!coefficient_vector_zero(&out1)) {
    printf("coefficient_vector_zero failed\n");
    return false;
  }
  coefficient_vector zero(out1.q_, out1.len_);
  if (!coefficient_vector_zero(&zero)) {
    printf("coefficient_vector_zero failed\n");
    return false;
  }

  if (!coefficient_equal(zero, out1)) {
    printf("coefficient_vector_zero zero failed\n");
    printf("out1 (%d): \n", (int)out1.c_.size());
    print_coefficient_vector(out1);
    printf("\n");
    printf("zero (%d): \n", (int)zero.c_.size());
    print_coefficient_vector(zero);
    printf("\n");
    return false;
  }

  if (!coefficient_vector_add_to(out2, &out1)) {
    printf("coefficient_vector_add_to failed\n");
    return false;
  }
  if (!coefficient_equal(out1, out2)) {
    printf("out 1 != out2 after add_to\n");
    return false;
  }

  return true;
}

bool random_module_vector_fill(module_vector* v, int k_h) {
  for (int i = 0; i < v->dim_; i++) {
    if (!coefficient_vector_zero(v->c_[i])) {
      return false;
    }
    for (int k = 0; k < k_h; k++) {
      unsigned t = 0;
      int l = crypto_get_random_bytes(3, (byte*)&t);
      t %= v->q_;
      v->c_[i]->c_[k] = (int)t;
    }
  }
  return true;
}

bool test_module_arith() {

    dilithium_parameters params;
    init_dilithium_parameters(&params);

  if (FLAGS_print_all) {
    print_dilithium_parameters(params);
  }

  module_array A(params.q_, 256, params.k_, params.l_);
  module_vector t(params.q_, params.n_, params.k_);
  module_vector s1(params.q_, params.n_, params.l_);
  module_vector s2(params.q_, params.n_, params.k_);
  module_vector s3(params.q_, params.n_, params.l_);
  module_vector s4(params.q_, params.n_, params.k_);

  if (FLAGS_print_all) {
    printf("A.q_: %d, A.n_: %d, A.nr_: %d, A.nc_: %d\n",
      A.q_, A.n_, A.nr_, A.nc_);
  }

#ifdef RANDOM_A
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
        A.c_[A.index(r, c)]->c_[k] = t;
      }
    }
  }
#else
  for (int r = 0; r < A.nr_; r++) {
    for (int c = 0; c < A.nc_; c++) {
      for (int k = 0; k < params.n_; k++) {
        coefficient_vector* vp = A.c_[A.index(r, c)];
        if (vp == nullptr)
          continue;
        A.c_[A.index(r, c)]->c_[k] = 0;
      }
    }
  }
  A.c_[A.index(0, 0)]->c_[0] = 2;
  A.c_[A.index(1, 1)]->c_[0] = 2;
  A.c_[A.index(2, 2)]->c_[0] = 2;
  A.c_[A.index(3, 0)]->c_[0] = 3;
  A.c_[A.index(3, 3)]->c_[0] = 1;
  A.c_[A.index(4, 0)]->c_[0] = 1;
  A.c_[A.index(4, 1)]->c_[0] = 1;
  A.c_[A.index(4, 2)]->c_[0] = 1;
  A.c_[A.index(4, 3)]->c_[0] = 1;
#endif

#ifdef RANDOM_A
  if (!random_module_vector_fill(&s1, 4)) {
    printf("random_module_vector_fill (1) failed\n");
    return false;
  }
  if (!random_module_vector_fill(&s2, 4)) {
    printf("random_module_vector_fill (2) failed\n");
    return false;
  }
  if (!random_module_vector_fill(&s3, 4)) {
    printf("random_module_vector_fill (3) failed\n");
    return false;
  }
  if (!random_module_vector_fill(&s4, 4)) {
    printf("random_module_vector_fill (4) failed\n");
    return false;
  }
#else
  make_module_vector_zero(&s1);
  make_module_vector_zero(&s2);
  s1.c_[0]->c_[0] = 1;
  s1.c_[1]->c_[0] = 2;
  s1.c_[2]->c_[0] = 3;
  s1.c_[3]->c_[0] = 4;
#endif

  module_vector r1(params.q_, params.n_, params.l_);
  module_vector r2(params.q_, params.n_, params.k_);
  module_vector rt1(params.q_, params.n_, params.l_);
  module_vector rt2(params.q_, params.n_, params.k_);

  if (!module_vector_subtract(s1, s1, &r1)) {
    printf("module_vector_subtract fails (1) %d %d %d\n", s1.dim_, s1.dim_, r1.dim_);
    print_module_vector(r1);
    printf("\n");
    return false;
  }
  if (!module_vector_is_zero(r1)) {
    printf("module_vector_subtract fails (1.5)\n");
    print_module_vector(r1);
    printf("\n");
    return false;
  }
  if (!module_vector_add(s1, s1, &r1)) {
    printf("module_vector_add fails (1)\n");
    return false;
  }

  if (FLAGS_print_all) {
    printf("s1:\n");
    print_module_vector(s1);
    printf("s1+s1=:\n"); 
    print_module_vector(r1);
    printf("\n");
  }

  coefficient_vector scalar(s1.q_, s1.n_);
  if (!coefficient_vector_zero(&scalar)) {
    printf("Can't zero scalar\n");
    return false;
  }
  scalar.c_[0] = 1;
  scalar.c_[2] = 1;

  if (!make_module_vector_zero(&rt1)) {
    return false;
  }
  if (!module_vector_mult_by_scalar(scalar, s1, &rt1)) {
    printf("module_vector_mult_by_scalar failed\n");
    return false;
  }

  if (FLAGS_print_all) {
    printf("scalar: \n");
    print_coefficient_vector(scalar);
    printf("\ns1: \n");
    print_module_vector(s1);
    printf("\nscalar * s1: \n");
    print_module_vector(rt1);
    printf("\n");
  }

  if (!make_module_vector_zero(&rt2)) {
    printf("Can't zero rt1\n");
    return false;
  }
  if (!module_apply_array(A, s1, &rt2)) {
    printf("module_apply_array failed\n");
    return false;
  }

#ifndef RANDOM_A
  if (rt2.c_[0]->c_[0] != 2 || rt2.c_[1]->c_[0] != 4 ||
      rt2.c_[2]->c_[0] != 6 || rt2.c_[3]->c_[0] != 7 ||
      rt2.c_[4]->c_[0] != 10) {
    printf("Apply gives wrong answer\n");
    return false;
  }
#endif

  if (FLAGS_print_all) {
    printf("A: \n");
    print_module_array(A);
    printf("\ns1: \n");
    print_module_vector(s1);
    printf("\nrt2: \n");
    print_module_vector(rt2);
    printf("\n");
  }

  return true;
}

bool test_dilithium1() {
  return true;

  dilithium_parameters params;
  init_dilithium_parameters(&params);

  if (FLAGS_print_all) {
    print_dilithium_parameters(params);
  }

  module_array A(params.q_, 256, params.k_, params.l_);
  module_vector t(params.q_, params.l_, params.n_);
  module_vector s1(params.q_, params.k_, params.n_);
  module_vector s2(params.q_, params.l_, params.n_);
  
  if (FLAGS_print_all) {
    printf("A.q_: %d, A.n_: %d, A.nr_: %d, A.nc_: %d\n",
      A.q_, A.n_, A.nr_, A.nc_);
  }

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
  return true;

  if (!dilithium_keygen(params, &A, &t, &s1, &s2)) {
    printf("dilithium_keygen failed\n");
    return false;
  }

  if (FLAGS_print_all) {
    printf("A:\n");
    print_module_array(A);
    printf("t:\n");
    print_module_vector(t);
    printf("\n");
    printf("s1:\n");
    print_module_vector(s1);
    printf("\n");
    printf("s2:\n");
    print_module_vector(s2);
    printf("\n");
  }

  int m_len = 3;
  byte M[3] = {0x1, 0x2, 0x3};

  if (FLAGS_print_all) {
    printf("To sign: ");
    print_bytes(3, M);
    printf("\n");
  }

  module_vector z(params.q_, params.l_, params.n_);
  int len_c = 256;
  byte c[len_c];
  if (!dilithium_sign(params,  A, t, s1, s2, m_len, M, &z, len_c, c)) {
    printf("dilithium_sign failed\n");
    return false;
  }

  if (FLAGS_print_all) {
    printf("z:\n");
    print_module_vector(z);
    printf("\n");
    printf("c:\n");
    print_bytes(len_c, c); 
    printf("\n");
  }

  if (dilithium_verify(params,  A,  t, m_len, M, z, len_c, c)) {
    printf("dilithium_verify succeeded\n");
  } else {
    printf("dilithium_verify failed\n");
    return false;
  }

  return true;
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
TEST (dilithium, test_dilithium1) {
  EXPECT_TRUE(test_dilithium1());
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
