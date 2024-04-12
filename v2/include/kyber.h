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
// File: kyber.h

#ifndef _KYBER_H__
#define _KYBER_H__

#include "crypto_support.h"
#include "symmetric_cipher.h"
using namespace std;

int round(int a, int b);
int compress(int q, int x, int d);
int decompress(int q, int x, int d);

class kyber_parameters {
public:
  kyber_parameters();
  ~kyber_parameters();
  bool init_kyber(int ks);

  int q_;
  int n_;
  int k_;
  int du_;
  int dv_;
  int dt_;

  int gamma_;

  int eta1_;
  int eta2_;
  int beta_;
};

class short_coefficient_vector {
public:
  int q_;
  int len_;

  short_coefficient_vector(int q, int len);
  ~short_coefficient_vector();

  vector<short int> c_;
};

class coefficient_vector {
public:
  int q_;
  int len_;

  coefficient_vector(int q, int len);
  ~coefficient_vector();

  vector<int> c_;
};

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

byte bit_reverse(byte b);
bool ntt_base_mult(short int q, short int g, int& in1, int& in2, int* out);
short int exp_in_ntt(short int q, short int e, short int base);
bool sample_ntt(int l, byte* b, short int* out);
bool sample_poly_cbd(int q, int eta, int l, short int* out);
bool ntt(coefficient_vector& in, coefficient_vector* out);
bool ntt_inv(coefficient_vector& in, coefficient_vector* out);
bool ntt_add(coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out);
bool ntt_mult(coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out);

bool coefficient_add(coefficient_vector& in1, coefficient_vector& in2,
    coefficient_vector* out);
bool coefficient_mult(coefficient_vector& in1, coefficient_vector& in2,
    coefficient_vector* out);
void print_coefficient_vector(coefficient_vector& v);
bool coefficient_set_vector(coefficient_vector& in, coefficient_vector* out);
bool coefficient_vector_zero(coefficient_vector* out);
bool coefficient_vector_add_to(coefficient_vector& in, coefficient_vector* out);
bool coefficient_equal(coefficient_vector& in1, coefficient_vector& in2);

bool short_coefficient_add(short_coefficient_vector& in1, short_coefficient_vector& in2,
    short_coefficient_vector* out);
bool short_coefficient_mult(short_coefficient_vector& in1, short_coefficient_vector& in2,
    short_coefficient_vector* out);
void print_short_coefficient_vector(short_coefficient_vector& v);
bool short_coefficient_set_vector(short_coefficient_vector& in,
      short_coefficient_vector* out);
bool short_coefficient_vector_zero(short_coefficient_vector* out);
bool short_coefficient_vector_add_to(short_coefficient_vector& in,
      short_coefficient_vector* out);
bool short_coefficient_equal(short_coefficient_vector& in1,
      short_coefficient_vector& in2);

void print_module_array(module_array& ma);
bool module_vector_mult_by_scalar(coefficient_vector& in1, module_vector& in2,
    module_vector* out);
bool module_vector_add(module_vector& in1, module_vector& in2,
    module_vector* out);
bool module_vector_subtract(module_vector& in1, module_vector& in2,
    module_vector* out);
bool module_apply_array(module_array& A, module_vector& v, module_vector* out);
bool module_vector_is_zero(module_vector& in);
bool make_module_vector_zero(module_vector* out);
bool module_vector_equal(module_vector& in1, module_vector& in2);
void print_module_vector(module_vector& mv);

void print_kyber_parameters(kyber_parameters& p);

#endif
