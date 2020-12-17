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

  vector_zero(&v_t);
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
  vector_zero(&v_t);
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
  vector_zero(&v_t);
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
  vector_zero(&v_t);
  if (!vector_dot_product(n, b[0], b[0], &d))
    return false;
  if (FLAGS_print_all) {
    print_vector(b[0]);
    printf(" * ");
    print_vector(b[0]);
    printf(" = ");
    printf("%lf\n", d);
  }
  vector_zero(&v_t);
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
  if (a != 1LL)
    return false;
  x = .87;
  a =  closest_int(x);
  if (FLAGS_print_all) {
    printf("close(%lf) = %lld\n", x, a);
  }
  if (a != 1LL)
    return false;
  x = -1.33;
  a =  closest_int(x);
  if (FLAGS_print_all) {
    printf("close(%lf) = %lld\n", x, a);
  }
  if (a != -1LL)
    return false;
  x = -.87;
  a =  closest_int(x);
  if (FLAGS_print_all) {
    printf("close(%lf) = %lld\n", x, a);
  }
  if (a != -1LL)
    return false;

  printf("matrix index\n");
  int nr = 8;
  int nc = 4;
  int i, j, k;
  for (int i = 0; i < nr; i++) {
    for (int j = 0; j < nc; j++) {
      k = matrix_index(nr,nc,i,j);
      printf("(%d, %d, %d, %d): %d\n", nr,nc,i,j,k);
    }
  }

  printf("matrix transpose index\n");
  for (int i = 0; i < nr; i++) {
    for (int j = 0; j < nc; j++) {
      k = matrix_transpose_index(nr,nc,i,j);
      printf("(%d, %d, %d, %d): %d\n", nr,nc,i,j,k);
    }
  }

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
    printf("v_t size; %d\n", (int)v_t.size());
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

  if (FLAGS_print_all)
    printf("q: %d\n", q);

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
    printf("q: %d\n", q);
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
  int64_t q = 1LL << 16;
  int64_t x;

  for (int i = 0; i < 5; i++) {
    if (!random_from_q(q, &x))
      return false;
    if (FLAGS_print_all)
      printf(" %llx ", x);

  }
  if (FLAGS_print_all)
    printf("\n");

  chi_dist rn;

  if (!rn.init(6)) 
    return false;
  for (int i = 0; i < 13; i++) {
    printf("%.4lf ", rn.probs_[i]);
  }
  printf("\n");

  for (int i = 0; i < 40; i++) {
    if (!rn.random_from_chi(&x))
      return false;
    printf("%lld ", x);
  }
  printf("\n");
  return true;
}

// A  8 x 4
int64_t A_t[8 * 4] = {
   9,  5, 11, 13,
  13,  6,  6,  2,
   6, 21, 17, 18,
  22, 19, 20,  8,
   2, 17, 10, 21,
  10,  8, 17, 11,
   5, 16, 12,  2,
   5,  7, 11,  7,
};

// S 4 x 4
int64_t S_t[4 * 4] = {
  5,  2,  9,  1,
  6,  8, 19,  1,
 19, 18,  9, 18,
  9,  2, 14, 18,
};

// E 8 x 4
int64_t E_t[8 * 4] = {
   0, 22,  1,  21,
   0, 22, 22,  22,
  22, 22, 22,   0,
   0,  0,  0,   0,
   0,  0,  1,   2,
   1,  0,  0,   1,
   1, 22,  1,  22,
  22,  0,  0,   1,
};

// P 8 x 4
int64_t P_t[8 * 4] = {
  10,  5, 21,  7,
   3,  1, 13,  1,
  19, 15,  6, 13,
   9, 20,  0, 16,
   8, 17, 13,  4,
  15, 21, 20, 17,
   0, 12,  3, 19,
  16,  2,  7, 15,
};

int msg_t[4] = {
  1, 0, 1, 1
};

int a_t[8] = {
  1, 1, 0, 1, 0, 0, 0, 1
};

int u_t[4] =  {
  3, 14, 2, 7
};

int c_t[4] =  {
  4, 5, 7, 5
};

// Test case: n=4, q=23, m=8, l = 4, alpha=5/23, s= 5
//   v 1,0,1,1
//   a 11010001
//   (u,c) (3,14,2,7), (4,5,7,5)
//   c-S^Tu 11 21 12 10
//   recover  1 0 1 1

bool test_lwe() {

  int l = 4;
  int m = 8;
  int n = 4;
  int64_t q = 23;
  int s_param = 5;
  int b;
  int_vector msg(4);
  int_vector a(8);
  int_vector u(4);
  int_vector c(4);
  int_vector recovered_msg(4);

  zero_int_vector(a);
  zero_int_vector(msg);
  zero_int_vector(u);
  zero_int_vector(c);
  zero_int_vector(recovered_msg);

  for (int i = 0; i < l; i++)
    msg[i] = msg_t[i];
  for (int i = 0; i < m; i++)
    a[i] = a_t[i];

  lwe lw;

  if (FLAGS_print_all) {
    printf("lwe (1)\nl: %d, m: %d, n: %d, q: %d, s: %d\n", l, m, n, (int)q, s_param);
  }

  if (!lw.init(l, m, n, q, s_param))
    return false;

  if (FLAGS_print_all) {
    printf("\nA:\n"); print_int_matrix(m, n, lw.A_); printf("\n");
    printf("\nS:\n"); print_int_matrix(n, l, lw.S_); printf("\n");
    printf("\nE:\n"); print_int_matrix(m, l, lw.E_); printf("\n");
    printf("\nP:\n"); print_int_matrix(m, l, lw.P_); printf("\n");
    printf("\nmsg: "); print_int_vector(msg); printf("\n");
    printf("a  : "); print_int_vector(a); printf("\n");
  }

  if (!lw.encrypt(msg, a, &u, &c))
    return false;
  if (FLAGS_print_all) {
    printf("(u, c): ");
    printf("( "); print_int_vector(u);
    printf(", "); print_int_vector(c);
    printf(" )\n");
  }

  if (!lw.decrypt(u, c, &recovered_msg))
    return false;
  if (FLAGS_print_all) {
    printf("recovered: "); print_int_vector(recovered_msg); printf("\n");
  }
  if (!int_vector_equal(msg, recovered_msg))
    return false;

  lwe lw2;

  if (FLAGS_print_all)
    printf("\nlwe (2)\nl: %d, m: %d, n: %d, q: %d, s: %d\n", l, m, n, (int)q, s_param);
  zero_int_vector(u);
  zero_int_vector(c);
  zero_int_vector(recovered_msg);

  if (!lw2.init(l, m, n, q, s_param))
    return false;

  lw2.debug_replace_params(A_t, S_t, E_t, P_t);
  if (FLAGS_print_all) {
    printf("\nA:\n"); print_int_matrix(m, n, lw2.A_); printf("\n");
    printf("\nS:\n"); print_int_matrix(n, l, lw2.S_); printf("\n");
    printf("\nE:\n"); print_int_matrix(m, l, lw2.E_); printf("\n");
    printf("\nP:\n"); print_int_matrix(m, l, lw2.P_); printf("\n");
    printf("\nmsg: "); print_int_vector(msg); printf("\n");
    printf("a  : "); print_int_vector(a); printf("\n");
  }

  if (!lw2.encrypt(msg, a, &u, &c))
    return false;
  if (FLAGS_print_all) {
    printf("(u, c): ");
    printf("( "); print_int_vector(u);
    printf(", "); print_int_vector(c);
    printf(" )\n");
  }

  if (!lw2.decrypt(u, c, &recovered_msg))
    return false;
  if (FLAGS_print_all) {
    printf("recovered: "); print_int_vector(recovered_msg); printf("\n");
  }
  if (!int_vector_equal(msg, recovered_msg)) {
    return false;
  }

  return true;
}


// NIST parameters test sizes

//    n=701, p=4096, q=3
bool test_big_ntru() {

#if 1
  int N = 701;  // reduction poly is (X^N - 1)
  int64_t p = 3LL;
  int64_t q = 4096LL;
  int d = 22;  // (q > (6d+1)p

  printf("\nntru\n");
  ntru nt;

  if (!nt.init(N, p, q, d)) {
    printf("inti failed\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("N: %d, p: %ld, q: %ld, d: %d\n", nt.N_, nt.p_, nt.q_, nt.d_);
    printf("f: "); print_poly(nt.n_, nt.f_); printf("\n");
    printf("fp: "); print_poly(nt.n_, nt.fp_); printf("\n");
    printf("g: "); print_poly(nt.n_, nt.g_); printf("\n");
    printf("fq: "); print_poly(nt.n_, nt.fq_); printf("\n");
    printf("h: "); print_poly(nt.n_, nt.h_); printf("\n");
    printf("gen: "); print_poly(nt.n_, nt.gen_); printf("\n");
  }

  // Message space is R(p), cipher space is R_q
  int64_t msg[N + 1];
  int64_t c[N + 1];
  int64_t r[N + 1];
  int64_t recovered[N + 1];

  // construct test message
  for (int j = 0; j < (N + 1); j++)
    msg[j] = j%2

  // construct r in T(d,d)
  if (!pick_T_values(N + 1, d, d, r))
    return false;

  if (FLAGS_print_all) {
    printf("msg: "); print_poly(nt.n_, msg); printf("\n");
    printf("r: "); print_poly(nt.n_, r); printf("\n");
  }
  if (!nt.encrypt(msg, r, c)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("c: "); print_poly(nt.n_, c); printf("\n");
  }
  if (!nt.decrypt(c, recovered)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("recovered: "); print_poly(nt.n_, recovered); printf("\n");
  }
#endif
  return true;
}

//    n=1344, q=2^16, |s| = 6
bool test_big_lwe() {

#if 1
  lwe obj;

  // l = B x m x n, 2^B <=q
  // int frodo_B = 4;
  // int frodo_m_bar = 8;
  // int frodo_n_bar = 8;
  // int frodo_l = frodo_B * frodo_m_bar * frodo_n_bar; // 256
  // int frodo_n = 1344;
  int frodo_n = 16;
  int frodo_l = frodo_n;
  int frodo_m = frodo_n + 16;  // m >= n
  int frodo_q = 1 << 16;
  int frodo_s = 6;

  if (FLAGS_print_all) {
    printf("lwe parameters\nl: %d, m: %d, n: %d, q: %d, s: %d\n", frodo_l,
       frodo_m, frodo_n, (int)frodo_q, frodo_s);
  }
  if (!obj.init(frodo_l, frodo_m, frodo_n, frodo_q, frodo_s)) {
    printf("lwe init failed\n");
    return false;
  }

  if (FLAGS_print_all) {
    printf("returned from init\n");
    //printf("\nA:\n"); print_int_matrix(obj.m_, obj.n_, obj.A_); printf("\n");
    //printf("\nS:\n"); print_int_matrix(obj.n_, obj.l_, obj.S_); printf("\n");
    //printf("\nE:\n"); print_int_matrix(obj.m_, obj.l_, obj.E_); printf("\n");
    //printf("\nP:\n"); print_int_matrix(obj.m_, obj.l_, obj.P_); printf("\n");
  }

  int_vector msg(frodo_l);
  int_vector a(frodo_m);
  int_vector u(frodo_n);
  int_vector c(frodo_l);
  int_vector recovered(frodo_l);

  zero_int_vector(a);
  zero_int_vector(msg);
  zero_int_vector(u);
  zero_int_vector(c);
  zero_int_vector(recovered);

  // fill msg and a
  for (int i = 0 ; i < frodo_l; i++)
    msg[i] = i%2;
  for (int i = 0 ; i < frodo_m; i++)
    a[i] = (i % 16);

  if (FLAGS_print_all) {
    printf("\nmsg: "); print_int_vector(msg); printf("\n");
    printf("a  : "); print_int_vector(a); printf("\n");
  }

  if (!obj.encrypt(msg, a, &u, &c)) {
    printf("lwe encrypt failed\n");
    return false;
  }

  if (FLAGS_print_all) {
    printf("returned from encrypt\n");
  }

  if (FLAGS_print_all) {
    printf("(u, c): ");
    printf("( "); print_int_vector(u);
    printf(", "); print_int_vector(c);
    printf(" )\n");
  }

  if (!obj.decrypt(u, c, &recovered)) {
    printf("lwe decrypt failed\n");
    return false;
  }

  if (FLAGS_print_all) {
    printf("returned from decrypt\n");
  }
  if (FLAGS_print_all) {
    printf("recovered: "); print_int_vector(recovered); printf("\n");
  }
  if (!int_vector_equal(msg, recovered))
    return false;
#endif
  return true;
}

bool test_int_support() {
  int64_t a = 23;
  int64_t b = 2;
  int64_t x = 0;
  int64_t y = 0;
  int64_t q = 0;
  int64_t r = 0;
  int64_t g = 0;

  if (!int_gcd(a, b, &x, &y, &g))
    return false;
  if (FLAGS_print_all) {
    printf("(%lld)(%lld) + (%lld)(%lld) = %lld\n", a,x,b,y,g);
  }
  if (g != 1)
    return false;

  if (!int_gcd(b, a, &y, &x, &g))
    return false;
  if (FLAGS_print_all) {
    printf("Reversed (%lld)(%lld) + (%lld)(%lld) = %lld\n", a,x,b,y,g);
  }
  if (g != 1)
    return false;

  a = 76;
  b = 74;
  x = 0;
  y = 0;
  q = 0;
  r = 0;
  g = 0;
  if (!int_gcd(a, b, &x, &y, &g))
    return false;
  if (FLAGS_print_all) {
    printf("(%lld)(%lld) + (%lld)(%lld) = %lld\n", a,x,b,y,g);
  }
  if (g != 2)
    return false;

  a = 16 * 5;
  b = 6 * 5;
  x = 0;
  y = 0;
  q = 0;
  r = 0;
  g = 0;
  if (!int_gcd(a, b, &x, &y, &g))
    return false;
  if (FLAGS_print_all) {
    printf("(%lld)(%lld) + (%lld)(%lld) = %lld\n", a,x,b,y,g);
  }
  if (g != 10)
    return false;

  return true;
}

bool test_poly_support() {
  int64_t poly_1[10] = {
    1LL, 1LL, 3LL, 0LL, 5LL,
    0LL, 0LL, 0LL, 0LL, 0LL
  };
  int64_t poly_2[10] = {
    1LL, 1LL, 5LL, 4LL, 5LL,
    0LL, 0LL, 0LL, 0LL, 0LL
  };
  int64_t poly_3[10];
  int64_t poly_4[10];
  int64_t poly_5[10];
  int n = 10;
  int64_t  modulus = 11;

 int64_t reducing_poly[12] = {
    1LL, 1LL, 1LL, 0LL, 0LL,
    0LL, 0LL, 0LL, 0LL, 0LL,
    0LL, 1LL,
  };

  if (FLAGS_print_all) {
    printf("\npoly 1, degree %d: ", poly_degree(10, poly_1));
    print_poly(10, poly_1);
    printf("\n");
    printf("poly 2, degree %d: ", poly_degree(10, poly_2));
    print_poly(10, poly_2);
    printf("\n");
    poly_zero(10, poly_3);
    printf("zeroed poly, degree %d: ", poly_degree(10, poly_3));
    printf("\n");
    poly_copy(10, poly_2, poly_4);
    printf("copied poly 2, degree %d: ", poly_degree(10, poly_4));
    print_poly(10, poly_4);
    printf("\n");
  }
  if (!poly_equal(10, poly_4, poly_2))
    return false;
  if (!poly_add_mod_poly(n, modulus, poly_1, poly_2, poly_5))
    return false;
  if (FLAGS_print_all) {
    printf("\n");
    print_poly(n, poly_1); printf(" + ");
    print_poly(n, poly_2); printf(" = ");
    print_poly(n, poly_5); printf("(mod %lld)\n ", modulus);
  }
  int64_t a_test[10] = {
    2, 2, 8, 4, 10,
    0, 0, 0, 0, 0
  };
  if (!poly_equal(n, a_test, poly_5))
    return false;

  if (!poly_sub_mod_poly(n, modulus, poly_1, poly_1, poly_5))
    return false;
  if (FLAGS_print_all) {
    printf("\n");
    print_poly(n, poly_1); printf(" - ");
    print_poly(n, poly_1); printf(" = ");
    print_poly(n, poly_5); printf("(mod %lld)\n ", modulus);
  }
  if (!poly_equal(n,poly_3, poly_5))
    return false;

  int64_t d = 3;
  if (!poly_mult_by_const(n, modulus, d, poly_1, poly_5))
    return false;
  if (FLAGS_print_all) {
    printf("\n");
    printf(" %lld * ", d);
    print_poly(n, poly_1); printf(" = ");
    print_poly(n, poly_5); printf(" (mod %lld)\n ", modulus);
  }
  int64_t m_test[10] = {
     3, 3, 9, 0, 4,
     0, 0, 0, 0, 0
  };
  if (!poly_equal(n, m_test, poly_5))
    return false;

  poly_zero(10, poly_5);
  if (!poly_mult_mod_poly_and_reduce(n, modulus, reducing_poly, poly_1, poly_2, poly_5))
    return false;
  if (FLAGS_print_all) {
    printf("\n");
    printf("Reducing poly: ");print_poly(n, reducing_poly); printf("(mod %lld)\n ", modulus);
    print_poly(n, poly_1); printf(" * ");
    print_poly(n, poly_2); printf(" = ");
    print_poly(n, poly_5); printf("(mod %lld)\n ", modulus);
    printf("Reduced by: "); print_poly(n, reducing_poly); printf("(mod %lld)\n ", modulus);
  }
  int64_t mm_test[10] = {
    8, 6, 0, 0, 0,
    0, 0, 0, 0, 0
  };
  if (!poly_equal(n, mm_test, poly_5))
    return false;

  poly_zero(10, poly_2);
  if (!poly_mult_mod_poly(n, modulus,  poly_1, poly_1, poly_2))
    return false;
  poly_zero(10, poly_4);
  poly_zero(10, poly_5);
  if (!poly_euclid(n, modulus, poly_2, poly_1, poly_4, poly_5))
    return false;
  if (FLAGS_print_all) {
    printf("\nEuclid: \n");
    print_poly(n, poly_2); printf(" =\n");
    print_poly(n, poly_1); printf(" * \n");
    print_poly(n, poly_4); printf(" +\n");
    print_poly(n, poly_5); printf("\n");
  }
  poly_2[0] = (poly_2[0] + 1LL) % modulus;
  poly_zero(10, poly_3);
  poly_zero(10, poly_4);
  poly_zero(10, poly_5);
  if (!poly_gcd(n, modulus, poly_2, poly_1, poly_3, poly_4, poly_5))
    return false;
  if (FLAGS_print_all) {
    printf("[ "); print_poly(n, poly_2); printf(" ] ");
    printf(" [ "); print_poly(n, poly_3); printf(" ] + ");
    printf("[ "); print_poly(n, poly_1); printf(" ] ");
    printf(" [ "); print_poly(n, poly_4); printf(" ] = ");
    printf(" [ "); print_poly(n, poly_5); printf(" ]\n");
  }
  poly_zero(10, poly_3);
  poly_zero(10, poly_4);
  poly_zero(10, poly_5);
  if (!poly_inverse_mod_poly(n, modulus, poly_2, poly_1, poly_5))
    return false;
  if (FLAGS_print_all) {
    printf("[ "); print_poly(n, poly_1); printf(" ] ^ (-1) ");
    printf("(mod  [ "); print_poly(n, poly_2); printf(" ]) = ");
    printf("[ "); print_poly(n, poly_5); printf(" ]\n");
  }

  return true;
}

/*
  Example
    N=5, p=3, q=29, d=1
    f in T(2,1) = x^4+x^3-1
    g in T(1,1) = x^3-x^2
    fp = -x^3-x^2+x-1, fq=-5x^4+8x^3+3x^2+11x+13
    h = fqg =8x^4+2x^3+11x^2+13x-5 (29)
    sk = f
    pk = (N, p, q, h)
    m = x^3 + x, r = x^4 -x
    c = prh + m = 8x^4+21x^3+25x^2+20x+15 (29)
    a = -2x^4+2x^3+4x^2-3x+1
    r = x^4 - x
    verify:a == prg+fm in R 
 */
int64_t test_f[6] = {
  -1, 0, 0, 1, 1, 0
};
int64_t test_g[6] = {
  0, 0, -1, 1, 0, 0
};
int64_t test_fp[6] = {
  -1, 1, -1, -1, 0, 0
};
int64_t test_fq[6] = {
  13, 11, 3, 5, 0, 0
};
int64_t test_h[6] = {
  -5, 13, 11, 2, 8, 0
};
int64_t test_m[6] = {
  0, 1, 0, 1, 0, 0
};
int64_t test_c[6] = {
  15, 20, 25, 21, 8, 0
};
int64_t test_a[6] = {
  1, -3, 4, 2, -2, 0
};
int64_t test_r[6] = {
  0, -1, 0, 0, 1, 0
};


bool test_ntru(bool fakeinit) {
  int N = 5;
  int64_t p = 3LL;
  int64_t q = 29LL;
  int d = 1;

  int64_t t_values[N+1];
  if (!pick_T_values(N+1, d+1, d, t_values))
    return false;
  for (int j = 0; j < (N+1); j++)
    printf("%2ld ", t_values[j]);
  printf("\n");

  printf("\nntru\n");
  ntru nt;

  if (!nt.init(N, p, q, d)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("N: %d, p: %ld, q: %ld, d: %d\n", nt.N_, nt.p_, nt.q_, nt.d_);
    printf("f: "); print_poly(nt.n_, nt.f_); printf("\n");
    printf("fp: "); print_poly(nt.n_, nt.fp_); printf("\n");
    printf("g: "); print_poly(nt.n_, nt.g_); printf("\n");
    printf("fq: "); print_poly(nt.n_, nt.fq_); printf("\n");
    printf("h: "); print_poly(nt.n_, nt.h_); printf("\n");
    printf("gen: "); print_poly(nt.n_, nt.gen_); printf("\n");
  }

  if (fakeinit)
    nt.debug_set_parameters(test_f, test_g, test_fp, test_fq, test_h);

  int64_t msg[6];
  int64_t c[6];
  int64_t r[6];
  int64_t recovered[6];
  poly_copy(6, test_m, msg);
  poly_copy(6, test_r, r);

  if (FLAGS_print_all) {
    printf("msg: "); print_poly(nt.n_, msg); printf("\n");
    printf("r: "); print_poly(nt.n_, r); printf("\n");
  }
  if (!nt.encrypt(msg, r, c)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("c: "); print_poly(nt.n_, c); printf("\n");
  }
  if (!nt.decrypt(c, recovered)) {
    return false;
  }
  if (FLAGS_print_all) {
    printf("recovered: "); print_poly(nt.n_, recovered); printf("\n");
  }
  if (!poly_equal(nt.n_, msg, recovered)) {
    return false;
  }

  return true;
}


TEST (support, support_functions) {
  EXPECT_TRUE(test_support_functions());
  EXPECT_TRUE(test_matrix());
  EXPECT_TRUE(test_rng());
}

TEST (lll, test_lll) {
  EXPECT_TRUE(test_gso());
  EXPECT_TRUE(test_lll());
}

TEST (lwe_support, test_lwe_support) {
  EXPECT_TRUE(test_vector());
}

TEST (lwe, test_lwe) {
  EXPECT_TRUE(test_lwe());
  EXPECT_TRUE(test_big_lwe());
}

TEST (int_ntru_support, test_ntru_support) {
  EXPECT_TRUE(test_int_support());
  EXPECT_TRUE(test_poly_support());
}

TEST (ntru, test_ntru) {
  EXPECT_TRUE(test_ntru(true));
  //EXPECT_TRUE(test_ntru(false));
  //EXPECT_TRUE(test_big_ntru());
  //EXPECT_TRUE(test_big_ntru());
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
