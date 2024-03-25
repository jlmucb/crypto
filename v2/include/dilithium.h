//
// Copyright 2024 John Manferdelli, All Rights Reserved.
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
// File: dilithium.h.h

#ifndef _DILITHIUM_H__
#define _DILITHIUM_H__

#include "crypto_support.h"
#include "symmetric_cipher.h"

class dilithium_parameters {
public:
  dilithium_parameters();
  ~dilithium_parameters();

  int n_;
  int k_;
  int l_;
  int d_;

  int q_;
  int wt_c_;
  int gamma_1_;
  int gamma_2_;
  int eta_;
  int beta_;
};

class coefficient_vector {
public:
  coefficient_vector(int q, int len);
  ~coefficient_vector();
  int q_;
  int len_;

  int* c_;
};

class module_coefficients {
public:
  module_coefficients(int q, int dim);
  ~module_coefficients();
  int len_;

  coefficient_vector* c_;
};

bool coefficient_add(coefficient_vector& in1, coefficient_vector& in2,
    coefficient_vector* out);
bool coefficient_mult(coefficient_vector& in1, coefficient_vector& in2,
    coefficient_vector* out);

bool module_add(module_coefficients& in1, module_coefficients& in2, module_coefficients* out);
bool module_mult(module_coefficients& in1, module_coefficients& in2, module_coefficients* out);

class coefficient_array {
public:
  int q_;
  int n_r_;
  int n_c_;

  module_coefficients* c_;
  int index(int r, int c);
  coefficient_array();
  ~coefficient_array();
};

bool vector_add(coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out);
bool vector_mult(coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out);
bool vector_reduce(coefficient_vector& in, coefficient_vector* out);
bool apply_array(coefficient_array& A, coefficient_vector& v, coefficient_vector* out);
bool dilithium_keygen(dilithium_parameters& params, int* A, int* t, int* s1, int* s2);

void print_coefficient_vector(coefficient_vector& v);

void print_dilithium_parameters(dilithium_parameters& p);
bool init_dilithium_parameters(dilithium_parameters* p);

#endif
