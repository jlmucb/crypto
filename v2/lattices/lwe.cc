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

bool matrix_multiply(int64_t q, int nr_1, int nc_1, int nc_2, int64_t* A, int64_t* B, int64_t* C) {
  int64_t t = 0;

  for (int i = 0; i < nr_1; i++) {
    for (int j = 0; j < nc_2; j++) {
      t = 0;
      for (int k = 0; k < nc_2; k++) {
        t+= A[matrix_index(nr_1, nc_2, i, k)] * B[matrix_index(nc_1, nc_2, k, j)];
        t %= q;
      }
      C[matrix_index(nr_1, nc_2, i, j)] = t % q;
    }
  }
  return true;
}

// copy A to B
bool matrix_copy(int m, int n, int64_t* A, int64_t* B) { 
  int k;

  for (int i = 0; i < m; i++) {
    for (int j = 0; j < n; j++) {
      k = matrix_index(m, n, i, j);
      B[k] = A[k];
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

bool int_vector_equal(int_vector& x, int_vector& y) {
  if (x.size() != y.size())
    return false;
  for (int i = 0; i < (int)x.size(); i++) {
    if (x[i] != y[i])
      return false;
  }
  return true;
}

void print_int_matrix(int m, int n, int64_t* A) {
  for (int i = 0; i < m; i++) {
    for (int j = 0; j < n; j++) {
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
  for (int i = 0; i < (int)v.size(); i++) {
    v[i] = 0;
  }
}

bool matrix_add(int64_t q, int nr, int nc, int64_t* A, int64_t* B, int64_t* C) {
  for (int i = 0; i < nr; i++) {
    for (int j = 0; j < nc; j++) {
      C[matrix_index(nr, nc, i, j)] = (A[matrix_index(nr, nc, i, j)] + B[matrix_index(nr, nc, i, j)]) % q;
    }
  }
  return true;
}

bool matrix_scalar_multiply(int64_t q, int nr, int nc, const int64_t d, int64_t* A, int64_t* C) {
  for (int i = 0; i < nr; i++) {
    for (int j = 0; j < nc; j++) {
      C[matrix_index(nr, nc, i, j)] = (d * A[matrix_index(nr, nc, i, j)]) % q;
    }
  }
  return true;
}

bool apply_matrix(int64_t q, int nr, int nc, int64_t* A, int_vector& v, int_vector* w) {
  int64_t t;

  for (int i = 0; i < nr; i++) {
    t = 0;
    for (int j = 0; j < nc; j++) {
      t += A[matrix_index(nr, nc, i, j)] * v[j];
      t %= q;
    }
    (*w)[i] = t % q;
  }
  return true;
}

bool apply_matrix_transpose(int64_t q, int nr, int nc, int64_t* A, int_vector& v, int_vector* w) {
  int64_t t;

  for (int i = 0; i < nc; i++) {
    t = 0;
    for (int j = 0; j < nr; j++) {
      t += A[matrix_transpose_index(nr, nc, i, j)] * v[j];
      t %= q;
    }
    (*w)[i] = t % q;
  }
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
  if (A_ != nullptr) {
    delete []A_;
    A_ = nullptr;
  }
  if (S_ != nullptr) {
    delete []S_;
    S_ = nullptr;
  }
  if (E_ != nullptr) {
    delete []E_;
    E_ = nullptr;
  }
  if (P_ != nullptr) {
    delete []P_;
    P_ = nullptr;
  }
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

void make_positive(int64_t q, int_vector* w) {
  for (int i = 0; i < (int)w->size(); i++) {
    if ((*w)[i] < 0)
      (*w)[i] += q;
  }
}

// closer to 0 or q/2?
bool binary_round(int64_t d, int_vector& v, int_vector* w) {
  if (d == 0ULL)
    return false;

  double x, xd;
  xd = 1.0 / ((double)d);
  for (int i = 0; i < (int)v.size(); i++) {
    x = ((double)v[i]) * xd;
    (*w)[i] = closest_int(x);
  }
  return true;
}

//    v in {0,1}^l, a in {0,1}^m (random)
//    (u=A^Ta, c = P^Ta+close(q/2)v)
bool lwe::encrypt(int_vector& in, int_vector& a, int_vector* out1, int_vector* out2) {
  int_vector v_r(l_);
  int_vector v_t(l_);
  zero_int_vector(v_r);
  zero_int_vector(v_t);
  int64_t b;
  int64_t q_r = closest_int(((double)q_) / 2.0);

  if (!apply_matrix_transpose(q_, m_, n_, A_, a, out1))
    return false;
  if (!mult_int_vector_by_scalar(q_, m_, (int64_t) q_r, in, &v_r))
    return false;
  if (!apply_matrix_transpose(q_, m_, l_, P_, a, &v_t))
    return false;
  if (!add_int_vector(q_, l_, v_r, v_t, out2))
    return false;

  return true;
}

//  D = close(close(q/2)^(-1) (c - S^Tu)) mod 2
bool lwe::decrypt(int_vector& in1, int_vector& in2, int_vector* out) {
  int64_t q_2 = closest_int(((double)q_) / 2.0);
  int_vector v_u(l_);
  int_vector v_t(l_);

  if (!apply_matrix_transpose(q_, n_, l_, S_, in1, &v_u))
    return false;
  if (!mult_int_vector_by_scalar(q_, l_, -1ULL, v_u, &v_u))
    return false;
  if (!add_int_vector(q_, l_, in2, v_u, &v_t))
    return false;
  make_positive(q_, &v_t);
  if (!binary_round(q_2, v_t, &v_u))
    return false;
  for (int i = 0; i < l_; i++)
    (*out)[i] = (v_u[i] % 2);

  return true;
}

void lwe::debug_replace_params(int64_t* A_t, int64_t* S_t, int64_t* E_t, int64_t* P_t) {

  // A_ is m x n
  if (!matrix_copy(m_, n_, A_t, A_))
    return;
  // S_ is n x l
  if (!matrix_copy(n_, l_, S_t, S_))
    return;
  // E_ is m x l
  if (!matrix_copy(m_, l_, E_t, E_))
    return;
  // P_ is m x l
  if (!matrix_copy(m_, l_, P_t, P_))
    return;
}
