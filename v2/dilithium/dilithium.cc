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

dilithium_parameters::dilithium_parameters(int n, int k, int l, int q, int g_1, int g_2, int eta, int beta) {
  n_ = n;
  k_ = k;
  l_ = l;
  q_ = q;
  gamma_1_ = g_1;
  gamma_2_ = g_2;
  eta_ = eta;
  beta_= beta;
}


dilithium_parameters::~dilithium_parameters() {
}

bool module_add(module_coefficients& in1, module_coefficients& in2, module_coefficients* out) {
  return false;
}

bool module_mult(module_coefficients& in1, module_coefficients& in2, module_coefficients* out) {
  return false;
}

bool vector_add(coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out) {
  return false;
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

