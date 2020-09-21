// Copyright 2020 John Manferdelli, All Rights Reserved.
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
// File: lwe.cc

#include "crypto_support.h"
#include "lattice.h"
#include "big_num.h"
#include "big_num_functions.h"

typedef vector<uint64_t> int_vector;


// m, n, q, m >=n,  chi is error dist, s.  M= {0,1}^l
// C = Zq^n x Zq^l
// S in Zq^(m x l), A in Zq^(m x n), E in Zq^(m x l).
// E is chosen from chi.
// P = AS+E
// Encrypt:
//    v in {0,1}^l, a in {0,1}^m (random)
//    (u=A^Ta, c = P^Ta+close(q/2)v)
//  Decrypt
//    D = close(close(q/2)^(-1)) (c - S^Tu) mod 2
//
// sigma = s / sqrt(2 pi).  p(x) = 1/c exp(-x^2/(s sigma^2)), c= \sum_k exp(-k^2/(2 sigma^2))
class lwe {
public:
  bool initialized_;
  int l_;
  int m_;
  int n_;
  int s_;
  uint64_t q_;
  uint64_t* A_;
  uint64_t* S_;
  uint64_t* E_;
  uint64_t* P_;
  double sigma_;

  lwe();
  ~lwe();

  bool init(int l, int m, int n, const uint64_t q, const uint64_t s_param);
  bool encrypt(int size_in, byte* in, int_vector* out1, int_vector* out2);
  bool decrypt(int_vector& in1, int_vector& in2, int* size_out, byte* out);
};

bool matrix_multiply(uint64_t q, int n1, int n2, int n3, uint64_t* A, uint64_t* B, uint64_t* C) {
  return true;
}

bool matrix_add(uint64_t q, int n1, int n2, uint64_t* A, uint64_t* B, uint64_t* C) {
  return true;
}

bool matrix_scalar_multiply(uint64_t q, int n1, int n2, const uint64_t d, uint64_t* B, uint64_t* C) {
  return true;
}

bool apply_matrix(uint64_t q, int n1, int n2, uint64_t* A, int_vector& v, int_vector* w) {
  return true;
}

bool apply_matrix_transpose(uint64_t q, int n1, int n2, uint64_t* A, int_vector& v, int_vector* w) {
  return true;
}

bool add_int_vector(uint64_t q, int n, int_vector& x, int_vector& y, int_vector* z) {
  return false;
}

bool mult_int_vector_by_scalar(uint64_t q, int n, uint64_t d, int_vector& x, int_vector* z) {
  return false;
}

bool random_from_q(const uint64_t q, uint64_t* out) {
  uint64_t t = 0ULL;
  int num_bytes = 1;
  uint64_t u = 0xff;

  while (u < q) {
    u <<= 8;
    num_bytes++;
  }
  if (crypto_get_random_bytes(num_bytes, (byte*) &t) < 0) {
    return false;
  }
  *out = t % q;
  return true;
}

bool random_from_chi(double sigma, uint64_t* out) {
  return true;
}

lwe::lwe() {
  A_ = nullptr;
  S_ = nullptr;
  E_ = nullptr;
  P_ = nullptr;
  initialized_ = false;
}

lwe::~lwe() {
  // A_ = nullptr;
  // S_ = nullptr;
  // E_ = nullptr;
  // P_ = nullptr;
  initialized_ = false;
}

const double pi = 3.14159265358979323846;

bool lwe::init(int l, int m, int n, const uint64_t q, const uint64_t s_param) {

  q_ = q;
  s_ = s_param;
  l_ = l;
  n_ = n;
  m_ = m;
  sigma_ = ((double)s_) / sqrt(2.0 * pi);

  // S is n x l
  S_ = new uint64_t[n * l];
  if (S_ == nullptr)
    return false;
  // A is m x n
  A_ = new uint64_t[m * n];
  if (A_ == nullptr)
    return false;
  // E is m x l
  E_ = new uint64_t[m * l];
  if (E_ == nullptr)
    return false;
  // P is m x l
  P_ = new uint64_t[m * l];
  if (P_ == nullptr)
    return false;

  // fill A, S, E
  for (int i = 0; i < m; i++) {
    for (int j = 0; j < n; j++) {
      if (!random_from_q(q_, &A_[matrix_index(m, n, i, j)]))
        return false;
    }
  }
  for (int i = 0; i < n; i++) {
    for (int j = 0; j < l; j++) {
      if (!random_from_q(q_, &S_[matrix_index(n, l, i, j)]))
        return false;
    }
  }
  for (int i = 0; i < m; i++) {
    for (int j = 0; j < l; j++) {
      if (!random_from_chi(sigma_, &E_[matrix_index(m, l, i, j)]))
        return false;
    }
  }

  // Compute P = AS + E
  if (!matrix_multiply(q, m, n, l, A_, S_, P_))
    return false;
  if (!matrix_add(q, m, l, P_, E_, P_))
    return false;
  // PK = (A, P)
  // pk = S
  initialized_ = true;

  return initialized_;
}

bool lwe::encrypt(int size_in, byte* in, int_vector* out1, int_vector* out2) {
  int_vector a(m_);
  uint64_t b;

  for (int i = 0; i < m_; i++) {
    if (!random_from_q(q_, &b))
      return false;
    a[i] = b;
  }

  // turn in into a vector
  int_vector v_a(l_);
  int_vector v_r(l_);
  int_vector v_t(l_);
  int_vector c(l_);

  //    v in {0,1}^l, a in {0,1}^m (random)
  //    (u=A^Ta, c = P^Ta+close(q/2)v)
  if (!apply_matrix_transpose(q_, m_, n_, A_, v_a, out1))
    return false;
  int64_t q_r = closest_int(((double)q_) / 2.0);
  if (!mult_int_vector_by_scalar(q_, l_, (uint64_t) q_r, v_a, &v_r))
    return false;
  if (!apply_matrix_transpose(q_, m_, l_, P_, v_a, &v_t))
    return false;
  if (!add_int_vector(q_, l_,  v_r, v_t, out2))
    return false;

  return true;
}

bool lwe::decrypt(int_vector& in1, int_vector& in2, int* size_out, byte* out) {
  //  D = close(close(q/2)^(-1)) (c - S^Tu) mod 2
  return true;
}
