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
// File: lattice.h

#include "crypto_support.h"

#ifndef _CRYPTO_LATTICE_H__
#define _CRYPTO_LATTICE_H__

#include <vector>
using std::vector;

typedef vector<double> real_vector;
typedef vector<int64_t> int_vector;

inline int matrix_index(int n_rows, int n_cols, int i, int j) {
  return n_cols * i + j;
}

inline int matrix_transpose_index(int n_rows, int n_cols, int i, int j) {
  return n_cols * j + i;
}

void print_vector(real_vector& v);
bool vector_alloc(int n, real_vector* v);
bool vector_zero(real_vector* v);
bool vector_add(int n, real_vector& v1,  real_vector& v2, real_vector* v);
bool vector_sub(int n, real_vector& v1,  real_vector& v2, real_vector* v);
bool vector_scalar_mult(int n, const double d,  real_vector& v1, real_vector* v);
bool vector_dot_product(int n, real_vector& v1, real_vector& v2, double* dp);

int64_t closest_int(double x);

bool gso(int n, real_vector* b, real_vector* b_norm, double* u);
bool size_reduce(int n, real_vector* b, real_vector* b_norm, double* u);
bool lll(const double delta, int n, real_vector* b);

void zero_int_matrix(int n, int m, int64_t* A);
void zero_int_vector(int_vector& v);
void print_int_matrix(int n, int m, int64_t* A);
void print_int_vector(int_vector& v);
bool int_inverse(int64_t modulus, int64_t a, int64_t* inv);
bool int_vector_equal(int_vector& x, int_vector& y);
bool add_int_vector(int64_t q, int n, int_vector& x, int_vector& y, int_vector* z);
bool mult_int_vector_by_scalar(int64_t q, int n, int64_t d, int_vector& x, int_vector* z);
void euclid(int64_t a, int64_t b, int64_t* q, int64_t* r);
bool int_gcd(int64_t a, int64_t b, int64_t* x, int64_t* y, int64_t* g);

void print_matrix(int n, int m, double* u);
bool matrix_zero(int n, int m, double* u);
bool matrix_copy(int n1, int n2, int64_t* A, int64_t* B);
bool matrix_multiply(int64_t q, int nr_1, int nc_1, int nc_2, int64_t* A, int64_t* B, int64_t* C);
bool matrix_add(int64_t q, int nr, int nc, int64_t* A, int64_t* B, int64_t* C);
bool matrix_scalar_multiply(int64_t q, int nr, int nc, const int64_t d, int64_t* A, int64_t* C);
bool apply_matrix(int64_t q, int nr, int nc, int64_t* A, int_vector& v, int_vector* w);
bool apply_matrix_transpose(int64_t q, int nr, int nc, int64_t* A, int_vector& v, int_vector* w);

bool random_from_q(const int64_t q, int64_t* out);
bool random_from_chi(int s, int64_t* out);

const double pi = 3.14159265358979323846;

class chi_dist {
public:
  bool initialized_;
  int s_;
  double c_;
  double sigma_;
  double* probs_;
  int64_t  prec_;

  chi_dist();
  ~chi_dist();
  bool init(int s);
  bool random_from_chi(int64_t* out);
  double exp_f(int k);
  double prob(int k);
  void normalize();
};


class lwe {
public:
  bool initialized_;
  int l_;
  int m_;
  int n_;
  int s_;
  int64_t q_;
  int64_t* A_;      // m x n
  int64_t* S_;      // n x l
  int64_t* E_;      // m x l
  int64_t* P_;      // m x l
  double sigma_;

  lwe();
  ~lwe();

  bool init(int l, int m, int n, const int64_t q, const int s_param);
  bool encrypt(int_vector& in, int_vector& a, int_vector* out1, int_vector* out2);
  bool decrypt(int_vector& in1, int_vector& in2, int_vector* out);

  void debug_replace_params(int64_t* A_t, int64_t* S_t, int64_t* E_t, int64_t* P_t);
};

void print_poly(int n, int64_t* f);
int poly_degree(int n, int64_t* f);
bool poly_equal(int n, int64_t* f, int64_t* r);
bool poly_copy(int n, int64_t* f, int64_t* r);
bool poly_zero(int n, int64_t* f);
bool reduce(int64_t modulus, int m, int64_t* in, int n, int64_t* reducing_poly, int64_t* r);
bool poly_add_mod_poly(int n, int64_t modulus, int64_t* f,
                       int64_t* g, int64_t* r);
bool poly_sub_mod_poly(int n, int64_t modulus, int64_t* f,
                       int64_t* g, int64_t* r);
bool poly_mult_by_const(int n, int64_t modulus, int64_t d, int64_t* f,
                        int64_t* r);
bool poly_mult_mod_poly(int n, int64_t modulus, int64_t* f, int64_t* g, int64_t* r);
bool poly_mult_mod_poly_and_reduce(int n, int64_t modulus, int64_t* reducing_poly,
                        int64_t* f, int64_t* g, int64_t* r);
bool poly_euclid(int n, int64_t modulus, int64_t* a, int64_t* b, int64_t* q,
                 int64_t* r);
bool poly_gcd(int n, int64_t modulus, int64_t* a, int64_t* b, int64_t* x,
              int64_t* y, int64_t* g);
bool poly_inverse_mod_poly(int n, int64_t modulus, int64_t* f,
                           int64_t* g, int64_t* r);

bool pick_T_values(int n, int d1, int d2, int64_t* u);


class ntru {
public:
  bool initialized_;
  int N_;
  int n_;	  // N_+1
  int64_t p_;
  int64_t q_;
  int d_;
  int64_t* gen_;
  int64_t* f_;
  int64_t* g_;
  int64_t* fp_;
  int64_t* fq_;
  int64_t* h_;

  ntru();
  ~ntru();

  bool init(int N, int64_t p, int64_t q, int d);
  bool encode_msg();
  bool encrypt(int64_t* msg, int64_t* r, int64_t* c);
  bool decrypt(int64_t* c, int64_t* recovered);
  bool decode_msg();

  void debug_set_parameters(int64_t* f, int64_t* g, int64_t* fp, int64_t* fq, int64_t* h);
};

#endif
