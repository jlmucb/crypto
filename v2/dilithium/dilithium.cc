// Copyright 2014-2024, John Manferdelli, All Rights Reserved.
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
// File: dilithium.cc

#include "crypto_support.h"
#include "dilithium.h"

using namespace std;

coefficient_vector::coefficient_vector(int q, int dim) {
  q_ = q;
  len_ = dim;

  c_.resize(dim);
  for (int i = 0; i < dim; i++)
    c_[i] = 0;
}

coefficient_vector::~coefficient_vector() {
}

dilithium_parameters::dilithium_parameters() {
  n_ = 0;
  k_ = 0;
  l_ = 0;
  q_ = 0;
  gamma_1_ = 0;
  gamma_2_ = 0;
  d_ = 0;
  eta_ = 0;
  beta_= 0;
}

dilithium_parameters::~dilithium_parameters() {
}

void print_module_array(module_array& ma) {
}

void print_coefficient_vector(coefficient_vector& v) {
  if (v.c_.size() == 0)
    return;
  printf("(%d", v.c_[v.c_.size()-1]);
  for (int i = (int)v.c_.size() - 2; i>=0; i--)
    printf(", %d", v.c_[i]);
  printf(")");
}

void print_dilithium_parameters(dilithium_parameters& p) {
  vector<int> g1(10, 0);
  printf("Dilithium parameters, ");
  printf("q: %d, n: %d, k: %d, l: %d, d: %d, gamma 1: %d, gamma 2: %d, eta: %d, beta: %d\n",
      p.q_, p.n_, p.k_, p.l_, p.d_, p.gamma_1_, p.gamma_2_, p.eta_, p.beta_);
}

bool init_dilithium_parameters(dilithium_parameters* p) {
  p->q_ = (1<<23) - (1<<13) + 1;
  p->n_ = 256;
  p->k_ = 5;
  p->l_ = 4;
  p->d_ = 14;
  p->wt_c_ = 60;
  p->gamma_1_ = (p->q_ - 1) / 16;
  p->gamma_2_ = p->gamma_1_ / 2;
  p->eta_ = 5;
  p->beta_ = 275;
  return true;
}

bool vector_add(coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out) {
  if (in1.c_.size() != in2.c_.size() || out->c_.size() < in1.c_.size())
    return false;
  for (int i = 0; i < (int)in1.c_.size(); i++)
      out->c_[i] = (in1.c_[i] + in2.c_[i]) % in1.q_;
  return true;
}

int reduce(int a, int b, int q) {
  return (q + a - b) % q;
}

bool vector_mult(coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out) {
  // multiply and reduce by (x**in1.c_.size() + 1)
  if (in1.c_.size() != in2.c_.size())
    return false;

  vector<int> t_out;
  t_out.resize(2 * in1.c_.size() - 1);
  for (int i = 0; i < (int)t_out.size(); i++)
    t_out[i] = 0;

  for (int i = 0; i < (int)in1.c_.size(); i++) {
    for (int j = 0; j < (int)in2.c_.size(); j++) {
      t_out[i + j] = (t_out[i + j] + (in1.c_[i] * in2.c_[j])) % in1.q_;
    }
#if 0
    printf("t_out (%d): ", i);
    for (int k = t_out.size() - 1; k >= 0; k--)
      printf("%d ", t_out[k]);
  printf("\n");
#endif
  }

#if 0
  printf("t_out: ");
  for (int k = t_out.size() - 1; k >= 0; k--)
    printf("%d ", t_out[k]);
  printf("\n");
#endif

  int m = (int)in1.c_.size() - 1;
  for (int j = (2 * m); j > m; j--) {
    t_out[j -  m] = reduce(t_out[j - m], t_out[j], in1.q_);
  }

  for (int j = 0; j <= m; j++)
    out->c_[j] = t_out[j];

  return true;
}

bool apply_array(module_array& A, module_vector& v, module_vector* out) {
  return false;
}

// A is R_q[k*l]
// t is module coefficient vector of length l
// s1 is module coefficient vector of length l
// s2 is module coefficient vector of length k
bool dilithium_keygen(dilithium_parameters& params, int* A, int* t, int* s1, int* s2) {
  return false;
}

