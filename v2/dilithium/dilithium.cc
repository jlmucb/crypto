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

module_coefficients::module_coefficients(int q, int dim) {
}

module_coefficients::~module_coefficients() {
}

void print_module_coefficients(module_coefficients& mc) {
}

void print_coefficient_vector(coefficient_vector& v) {
  if (v.c_.size() == 0)
    return;
  printf("(%d", v.c_[0]);
  for (int i = 1; i < (int)v.c_.size(); i++)
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

bool module_add(module_coefficients& in1, module_coefficients& in2, module_coefficients* out) {
  return false;
}

bool module_mult(module_coefficients& in1, module_coefficients& in2, module_coefficients* out) {
  return false;
}

bool vector_add(coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out) {
  if (in1.c_.size() != in2.c_.size() || out->c_.size() < in1.c_.size())
    return false;
  for (int i = 0; i < (int)in1.c_.size(); i++)
      out->c_[i] = (in1.c_[i] + in2.c_[i]) % in1.q_;
  return true;
}

int reduce(int a, int b, int q) {
  // (b - a) % q
  return (q + b - a) % q;
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
      t_out[i + j] = (t_out[i + j] + (t_out[i] * t_out[j])) % in1.q_;
    }
  }

  int n = (int)in1.c_.size();
  for (int j = (2 * n - 1); j >= n; j--) {
    t_out[j - n] = reduce(t_out[j - n], t_out[j], in1.q_);
  }

  for (int j = 0; j < n; j++)
    out->c_[j] = t_out[j];

  return true;
}

bool apply_array(coefficient_array& A, coefficient_vector& v, coefficient_vector* out) {
  return false;
}

// A is R_q[k*l]
// t is module coefficient vector of length l
// s1 is module coefficient vector of length l
// s2 is module coefficient vector of length k
bool dilithium_keygen(dilithium_parameters& params, int* A, int* t, int* s1, int* s2) {
  return false;
}

