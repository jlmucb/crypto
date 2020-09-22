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

// LWE
//  m, n, q, m >=n,  chi is error dist, s.  M= {0,1}^l
//  C = Zq^n x Zq^l
//  S in Zq^(m x l), A in Zq^(m x n), E in Zq^(m x l).
//  E is chosen from chi.
//  P = AS+E
//  Encrypt:
//    v in {0,1}^l, a in {0,1}^m (random)
//    (u=A^Ta, c = P^Ta+close(q/2)v)
//  Decrypt
//    D = close(close(q/2)^(-1)) (c - S^Tu) mod 2
//
//  sigma = s / sqrt(2 pi).  p(x) = 1/c exp(-x^2/(s sigma^2)), c= \sum_k exp(-k^2/(2 sigma^2))

bool matrix_multiply(int64_t q, int n1, int n2, int n3, int64_t* A, int64_t* B, int64_t* C) {
  int64_t t = 0;

  for (int i = 0; i < n1; i++) {
    for (int j = 0; j < n3; j++) {
      t = 0;
      for (int k = 0; k < n2; k++) {
        t+= A[matrix_index(n1, n2, i, k)] * B[matrix_index(n2, n3, k, j)];
        t %= q;
      }
      C[matrix_index(n1, n3, i, j)] = t % q;
    }
  }
  return true;
}

void zero_int_matrix(int n, int m, int64_t* A) {
  for (int i = 0; i < n; i++) {
    for (int j = 0; j < m; j++) {
      A[matrix_index(m, n, i, j)] = 0;
    }
  }
}

void print_int_matrix(int n, int m, int64_t* A) {
  for (int i = 0; i < n; i++) {
    for (int j = 0; j < m; j++) {
      printf("%5lld  ", A[matrix_index(m, n, i, j)]);
    }
    printf("\n");
  }
}

void print_int_vector(int_vector& v) {
  printf("( ");
  for (int i = 0; i < v.size(); i++) {
    printf("%5lld  ", v[i]);
  }
  printf(" )");
}

void zero_int_vector(int_vector& v) {
  for (int i = 0; i < v.size(); i++) {
    v[i] = 0;
  }
}

bool matrix_add(int64_t q, int n1, int n2, int64_t* A, int64_t* B, int64_t* C) {
  for (int i = 0; i < n1; i++) {
    for (int j = 0; j < n2; j++) {
      C[matrix_index(n1, n2, i, j)] = (A[matrix_index(n1, n2, i, j)] + B[matrix_index(n1, n2, i, j)]) % q;
    }
  }
  return true;
}

bool matrix_scalar_multiply(int64_t q, int n1, int n2, const int64_t d, int64_t* A, int64_t* C) {
  for (int i = 0; i < n1; i++) {
    for (int j = 0; j < n2; j++) {
      C[matrix_index(n1, n2, i, j)] = (d * A[matrix_index(n1, n2, i, j)]) % q;
    }
  }
  return true;
}

bool apply_matrix(int64_t q, int n1, int n2, int64_t* A, int_vector& v, int_vector* w) {
  int64_t t;
  for (int i = 0; i < n1; i++) {
    t = 0;
    for (int j = 0; j < n2; j++) {
      t+= A[matrix_index(n1, n2, i, j)] * v[j];
      t %= q;
    }
    (*w)[i] = t % q;
  }
  return true;
}

bool apply_matrix_transpose(int64_t q, int n1, int n2, int64_t* A, int_vector& v, int_vector* w) {
  return true;
}

bool add_int_vector(int64_t q, int n, int_vector& x, int_vector& y, int_vector* z) {
  for (int i = 0; i < n; i++) {
    (*z)[i] = (x[i] + y[i]) % q;
  }
  return true;
}

bool mult_int_vector_by_scalar(int64_t q, int n, int64_t d, int_vector& x, int_vector* z) {
  for (int i = 0; i < n; i++) {
    (*z)[i] = (d * x[i]) % q;
  }
  return true;
}

bool random_from_q(const int64_t q, int64_t* out) {
  int64_t t = 0ULL;
  int num_bytes = 1;
  int64_t u = 0xff;

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

chi_dist::chi_dist() {
  probs_ = nullptr;
  initialized_ = false;
}

chi_dist::~chi_dist() {
  if (probs_ != nullptr)
    delete []probs_;
  probs_ = nullptr;
  initialized_ = false;
}

bool chi_dist::init(int s) {
  s_ = s;
  sigma_ = sqrt(2.0 * pi);
  probs_ = new double[2 * s + 1];
  normalize();
  double y = 0.0;
  for (int i = -s_; i <= s_; i++) {
    y += prob(i);
    probs_[s_ + i] = y;
  }
  prec_ = 1ULL << 32;
  initialized_ = true;
  return true;
}

bool chi_dist::random_from_chi(int64_t* out) {
  uint64_t u = 0.0;
  if (crypto_get_random_bytes(4, (byte*)&u) < 0)
    return false;
  double t = ((double)u) / ((double)prec_);
  for (int i = 0; i < 2 * s_ + 1; i++) {
    if (t <= probs_[i]) {
      *out = (int64_t)(i - s_);
      return(true); 
    }
  }
  *out = 0ULL;
  return true;
}

double chi_dist::prob(int k) {
  double t = (double)k;
  if (k < -s_ || k > s_)
    return 0.0;
  return c_ * exp_f(k);
}

double chi_dist::exp_f(int k) {
  double t = (double)k;
  if (k < -s_ || k > s_)
    return 0.0;
  t = (t * t) / (2.0 * sigma_ * sigma_);
  return exp(-t);
}

void chi_dist::normalize() {
  double t = 0.0; 
  for (int i = -s_; i <= s_; i++) {
    t+= exp_f(i);
  }
  c_ = 1.0 / t;
}

chi_dist g_rn;

bool random_from_chi(int s, int64_t* out) {

  if (!g_rn.initialized_) {
    if (!g_rn.init(s)) 
      return false;
  }
  if (!g_rn.initialized_)
    return false;

  if (!g_rn.random_from_chi(out))
    return false;
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


bool lwe::init(int l, int m, int n, const int64_t q, const int s_param) {

  q_ = q;
  s_ = s_param;
  l_ = l;
  n_ = n;
  m_ = m;
  sigma_ = ((double)s_) / sqrt(2.0 * pi);

  // S is n x l
  S_ = new int64_t[n * l];
  if (S_ == nullptr)
    return false;
  // A is m x n
  A_ = new int64_t[m * n];
  if (A_ == nullptr)
    return false;
  // E is m x l
  E_ = new int64_t[m * l];
  if (E_ == nullptr)
    return false;
  // P is m x l
  P_ = new int64_t[m * l];
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
  int64_t b;

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
  if (!mult_int_vector_by_scalar(q_, l_, (int64_t) q_r, v_a, &v_r))
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
