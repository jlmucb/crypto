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
using namespace std;

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

bool H(int in_len, byte* in, int* out_len, byte* out);
int inf_norm(vector<int> v);
int high_bits(int x, int a);
int low_bits(int x, int a);

class coefficient_vector {
public:
  int q_;
  int len_;

  coefficient_vector(int q, int len);
  ~coefficient_vector();

  vector<int> c_;
};

bool coefficient_add(coefficient_vector& in1, coefficient_vector& in2,
    coefficient_vector* out);
bool coefficient_mult(coefficient_vector& in1, coefficient_vector& in2,
    coefficient_vector* out);
bool coefficients_high_bits(int a, coefficient_vector& in, coefficient_vector* out);
bool coefficients_low_bits(int a, coefficient_vector& in, coefficient_vector* out);

class module_array {
public:
  int q_;
  int n_;
  int nr_;
  int nc_;

  module_array(int q, int n, int nr, int nc);
  ~module_array();

  coefficient_vector** c_;
  int index(int r, int c);
};

class module_vector {
public:
  int q_;
  int dim_;
  int n_;

  module_vector(int q, int n, int dim);
  ~module_vector();

  coefficient_vector** c_;
};

bool vector_add(coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out);
bool vector_mult(coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out);
void print_coefficient_vector(coefficient_vector& v);
void print_module_array(module_array& ma);

bool module_vector_add(module_vector& in1, module_vector& in2, module_vector* out);
bool module_apply_array(module_array& A, module_vector& v, module_vector* out);
void print_module_vector(module_vector& mv);

void print_dilithium_parameters(dilithium_parameters& p);
bool init_dilithium_parameters(dilithium_parameters* p);

bool dilithium_keygen(dilithium_parameters& params, module_array* A, module_vector* t,
                module_vector* s1, module_vector* s2);
bool dilithium_sign(dilithium_parameters& params,  module_array& A,  module_vector& t,
                module_vector& s1, module_vector& s2,
                module_vector* z, int len_c, byte* c);
bool dilithium_verify(dilithium_parameters& params,  module_array& A,  module_vector& t,
                module_vector& s1, module_vector& s2,
                module_vector& z, int len_c, byte* c);
#endif
