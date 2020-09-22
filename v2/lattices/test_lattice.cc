// Copyright 2020 John Manferdelli, All Rights Reserved.
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
// File: test_lattice.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "lattice.h"


DEFINE_bool(print_all, false, "Print intermediate test computations");

bool test_support_functions() {
  int n = 3;
  real_vector b[3];
  real_vector v_t;
  double d, x;

  vector_alloc(n, &v_t); 
  for (int i = 0; i < n; i++)
    vector_alloc(n, &b[i]); 

  (b[0])[0] = 2.0;
  (b[0])[1] = 3.0;
  (b[0])[2] = 14.0;
  (b[1])[0] = 0.0;
  (b[1])[1] = 7.0;
  (b[1])[2] = 11.0;
  (b[2])[0] = 0.0;
  (b[2])[1] = 0.0;
  (b[2])[2] = 23.0;

  vector_zero(n, &v_t);
  if (FLAGS_print_all) {
    print_vector(v_t);
    printf("\n");
  }

  if (!vector_add(n, b[0], b[1], &v_t))
    return false;
  if (FLAGS_print_all) {
    print_vector(b[0]);
    printf(" + ");
    print_vector(b[1]);
    printf(" = ");
    print_vector(v_t);
    printf("\n");
  }
  vector_zero(n, &v_t);
  if (!vector_sub(n, b[0],  b[1], &v_t))
    return false;
  if (FLAGS_print_all) {
    print_vector(b[0]);
    printf(" - ");
    print_vector(b[1]);
    printf(" = ");
    print_vector(v_t);
    printf("\n");
  }
  vector_zero(n, &v_t);
  x = 2.0;
  if (!vector_scalar_mult(n, x,  b[0], &v_t))
    return false;
  if (FLAGS_print_all) {
    printf("%lf  ", x);
    print_vector(b[0]);
    printf(" = ");
    print_vector(v_t);
    printf("\n");
  }
  vector_zero(n, &v_t);
  if (!vector_dot_product(n, b[0], b[0], &d))
    return false;
  if (FLAGS_print_all) {
    print_vector(b[0]);
    printf(" * ");
    print_vector(b[0]);
    printf(" = ");
    printf("%lf\n", d);
  }
  vector_zero(n, &v_t);
  if (!vector_dot_product(n, b[0], b[1], &d))
    return false;
  if (FLAGS_print_all) {
    print_vector(b[0]);
    printf(" * ");
    print_vector(b[1]);
    printf(" = ");
    printf("%lf\n", d);
  }

  x = 1.33;
  int64_t a =  closest_int(x);
  if (FLAGS_print_all) {
    printf("close(%lf) = %lld\n", x, a);
  }
  if (a != 1ULL)
    return false;
  x = .87;
  a =  closest_int(x);
  if (FLAGS_print_all) {
    printf("close(%lf) = %lld\n", x, a);
  }
  if (a != 1ULL)
    return false;
  x = -1.33;
  a =  closest_int(x);
  if (FLAGS_print_all) {
    printf("close(%lf) = %lld\n", x, a);
  }
  if (a != -1ULL)
    return false;
  x = -.87;
  a =  closest_int(x);
  if (FLAGS_print_all) {
    printf("close(%lf) = %lld\n", x, a);
  }
  if (a != -1ULL)
    return false;

  return true;
}

// lll tests
bool test_gso() {
  int n = 3;
  real_vector b[3];
  real_vector b_norm[3];
  real_vector v_t;
  double u[n * n];
  double d, x;
  matrix_zero(n, n, u);

  vector_alloc(n, &v_t); 
  for (int i = 0; i < n; i++)
    vector_alloc(n, &b[i]); 

  if (FLAGS_print_all) {
    printf("v_t size; %d\n", v_t.size());
  }

  (b[0])[0] = 2.0;
  (b[0])[1] = 3.0;
  (b[0])[2] = 14.0;
  (b[1])[0] = 0.0;
  (b[1])[1] = 7.0;
  (b[1])[2] = 11.0;
  (b[2])[0] = 0.0;
  (b[2])[1] = 0.0;
  (b[2])[2] = 23.0;

  if (FLAGS_print_all) {
    printf("Original vectors: \n");
    for (int i = 0; i < n; i++) {
      printf("\tb[%d]: ", i);
      print_vector(b[i]);
      printf("\n");
    }
  }

  if (!gso(n, b, b_norm, u))
    return false;

  if (FLAGS_print_all) {
    printf("Orthogonal vectors: \n");
    for (int i = 0; i < n; i++) {
      printf("\tb*[%d]: ", i);
      print_vector(b_norm[i]);
      printf("\n");
    }
  }

  return true;
}

bool test_size_reduce() {
  return true;
}

bool test_lll() {
  int n = 3;
  real_vector b[3];

  for (int i = 0; i < n; i++)
    vector_alloc(n, &b[i]); 

  (b[0])[0] = 2.0;
  (b[0])[1] = 3.0;
  (b[0])[2] = 14.0;
  (b[1])[0] = 0.0;
  (b[1])[1] = 7.0;
  (b[1])[2] = 11.0;
  (b[2])[0] = 0.0;
  (b[2])[1] = 0.0;
  (b[2])[2] = 23.0;

  // answer is (-2,4,-3), (-4,1,6), (4,6,5)
  if (FLAGS_print_all) {
    printf("Original vectors: \n");
    for (int i = 0; i < n; i++) {
      printf("\tb[%d]: ", i);
      print_vector(b[i]);
      printf("\n");
    }
  }

  if (!lll(.75, 3, b))
    return false;

  if (FLAGS_print_all) {
    printf("Reduced vectors: \n");
    for (int i = 0; i < n; i++) {
      printf("\tb[%d]: ", i);
      print_vector(b[i]);
      printf("\n");
    }
  }

  // The answer is:
  //    (-2, 4, 3), (-4, 1, 6), (4, 6, 5) 
  if ( (b[0])[0] != -2.0  || (b[0])[1] != 4.0  || (b[0])[2] != -3.0)
    return false;
  if ( (b[1])[0] != -4.0  || (b[1])[1] != 1.0  || (b[1])[2] != 6.0)
    return false;
  if ( (b[2])[0] != 4.0  || (b[2])[1] != 6.0  || (b[2])[2] != 5.0)
    return false;

  return true;
}

bool test_vector() {
  int_vector v1(5);
  int_vector v2(5);
  int_vector w(5);
  int n = 5;
  int q = 37;
  int64_t d = 3;

  printf("q: %lld\n", q);

  for (int i = 0; i < n; i++) {
    v1[i] = (int64_t) (i + 1);
    v2[i] = (int64_t) 3 * i;
  }

  if (!add_int_vector(q, n, v1, v2, &w))
      return false;
  if (FLAGS_print_all) {
    print_int_vector(v1);
    printf(" + ");
    print_int_vector(v2);
    printf(" = ");
    print_int_vector(w);
    printf("\n");
  }

  zero_int_vector(w);
  if (!mult_int_vector_by_scalar(q, n, d, v1, &w))
      return false;
  if (FLAGS_print_all) {
    printf(" %lld * ", d);
    print_int_vector(v1);
    printf(" = ");
    print_int_vector(w);
    printf("\n");
  }

  return true;
}

bool test_matrix() {
  int64_t A[5 * 5];
  int64_t B[5 * 5];
  int64_t C[5 * 5];
  int n = 5;
  int q = 37;
  int64_t d = 3;

  if (FLAGS_print_all) {
    printf("q: %lld\n", q);
  }

  for (int i = 0; i < n; i++) {
    for (int j = 0; j < n; j++) {
      A[matrix_index(n, n, i, j)] = (int64_t) (i + j);
      B[matrix_index(n, n, i, j)] = (int64_t) (5 * i + 4 * j);
    }
  }

  zero_int_matrix(n, n, C);
  if (!matrix_multiply(q, n, n, n, A, B, C))
    return false;
  if (FLAGS_print_all) {
    print_int_matrix(n, n, A);
    printf(" * \n");
    print_int_matrix(n, n, B);
    printf(" = \n");
    print_int_matrix(n, n, C);
    printf("\n");
  }

  zero_int_matrix(n, n, C);
  if (!matrix_scalar_multiply(q, n, n, d, A, C))
    return false;
  if (FLAGS_print_all) {
    printf(" %lld *\n", d);
    print_int_matrix(n, n, A);
    printf(" = \n");
    print_int_matrix(n, n, C);
    printf("\n");
  }

  zero_int_matrix(n, n, C);
  if (!matrix_add(q, n, n, A, B, C))
    return false;
  if (FLAGS_print_all) {
    print_int_matrix(n, n, A);
    printf(" + \n");
    print_int_matrix(n, n, B);
    printf(" = \n");
    print_int_matrix(n, n, C);
    printf("\n");
  }

  int_vector v(5);
  int_vector w(5);
  for(int i = 0; i < n; i++)
    v[i] = (int64_t) (1 + i % 2);

  if (!apply_matrix(q, n, n, A, v, &w))
    return false;
  if (FLAGS_print_all) {
    print_int_matrix(n, n, A);
    printf("  \n");
    print_int_vector(v);
    printf(" = \n");
    print_int_vector(w);
    printf("\n");
  }

  // apply_matrix_transpose(int64_t q, int n1, int n2, int64_t* A, int_vector& v, int_vector* w);
  return true;
}

bool test_rng() {
  // bool random_from_q(const int64_t q, int64_t* out);
  // bool random_from_chi(double sigma, int64_t* out);
  return true;
}

TEST (support, test_support) {
  EXPECT_TRUE(test_support_functions());
}
TEST (gso, test_gso) {
  EXPECT_TRUE(test_gso());
}
TEST (size_reduce, test_size_reduce) {
  EXPECT_TRUE(test_size_reduce());
}
TEST (lll, test_lll) {
  EXPECT_TRUE(test_lll());
}
TEST (vector, test_vector) {
  EXPECT_TRUE(test_vector());
}
TEST (rng, test_rng) {
  EXPECT_TRUE(test_rng());
}
TEST (matrix, test_matrix) {
  EXPECT_TRUE(test_matrix());
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
  return result;
}
