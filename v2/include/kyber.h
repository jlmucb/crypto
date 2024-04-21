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

byte bit_from_ints(int bits_in_int, int bit_numb, int* pi);
byte bit_from_bytes(int bit_numb, byte* buf);
bool byte_encode(int d, int n, int* pi, byte* out);
bool byte_decode(int d, int n, int in_len, byte* in, int* pi);

byte bit_from_int_vector(int bits_in_int, int bit_numb, vector<int>& v);
bool byte_encode_from_vector(int d, int n, vector<int>& v, byte* out);
bool byte_decode_to_vector(int d, int n, int in_len, byte* in, vector<int>& v);

bool G(int in_len, byte* in, int bit_out_len, byte* out);
bool prf(int eta, int in1_len, byte* in1, int in2_len, byte* in2, int bit_out_len, byte* out);
bool xof(int eta, int in1_len, byte* in1, int i, int j, int bit_out_len, byte* out);

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

class coefficient_array {
public:
  int q_;
  int nr_;
  int nc_;

  coefficient_array(int q, int nr, int nc);
  ~coefficient_array();

  int *a_;
  int index(int r, int c);
};

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
byte bit_in_byte_stream(int k, int l, byte* b);
bool rand_coefficient(int top, coefficient_vector& v);
bool fill_random_coefficient_array(coefficient_array* ma);
bool fill_random_module_array(module_array* ma);
bool rand_module_coefficients(int top, module_vector& v);

bool ntt_base_mult(int q, int g, int& in1a, int& in1b,
        int& in2a, int& in2b, int* outa, int* outb);
int exp_in_ntt(int q, int e, int base);

bool sample_ntt(int q, int l, int b_len, byte* b, vector<int>& out);
bool sample_poly_cbd(int q, int eta, int l, int b_len, byte* b, vector<int>& out);

bool ntt(int g, coefficient_vector& in, coefficient_vector* out);
bool ntt_inv(int g, coefficient_vector& in, coefficient_vector* out);
bool ntt_mult(int g, coefficient_vector& in1, coefficient_vector& in2, coefficient_vector* out);
bool multiply_ntt(int g, coefficient_vector& in1, coefficient_vector& in2,
        coefficient_vector* out);

bool coefficient_add(coefficient_vector& in1, coefficient_vector& in2,
    coefficient_vector* out);
bool coefficient_mult(coefficient_vector& in1, coefficient_vector& in2,
    coefficient_vector* out);
void print_coefficient_vector(coefficient_vector& v);
bool coefficient_set_vector(coefficient_vector& in, coefficient_vector* out);
bool coefficient_vector_zero(coefficient_vector* out);
bool coefficient_vector_add_to(coefficient_vector& in, coefficient_vector* out);
bool coefficient_equal(coefficient_vector& in1, coefficient_vector& in2);
bool coefficient_apply_array(coefficient_array& A, coefficient_vector& v, coefficient_vector* out);

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
bool module_vector_dot_product(module_vector& in1, module_vector& in2,
	coefficient_vector* out);
bool module_vector_dot_product_first_transposed(module_vector& in1,
	module_vector& in2, coefficient_vector* out);
bool ntt_module_vector_dot_product(module_vector& in1,
	module_vector& in2, coefficient_vector* out);
bool ntt_module_vector_dot_product_first_transposed(module_vector& in1,
	module_vector& in2, coefficient_vector* out);
void print_module_vector(module_vector& mv);

bool ntt_module_apply_array(int g, module_array& A, module_vector& v, module_vector* out);
bool ntt_module_apply_transpose_array(int g, module_array& A, module_vector& v, module_vector* out);

void print_kyber_parameters(kyber_parameters& p);

bool kyber_keygen(int g, kyber_parameters& p, int* ek_len, byte* ek,
      int* dk_len, byte* dk);
bool kyber_encrypt(int g, kyber_parameters& p, int ek_len, byte* ek,
      int m_len, byte* m, int b_r_len, byte* b_r, int* c_len, byte* c);
bool kyber_decrypt(int g, kyber_parameters& p, int dk_len, byte* dk,
      int c_len, byte* c, int* m_len, byte* m);

bool kyber_kem_keygen(kyber_parameters& p, int* kem_ek_len, byte* kem_ek,
      int* kem_dk_len, byte* kem_dk);
bool kyber_kem_encaps(kyber_parameters& p, int kem_ek_len, byte* kem_ek,
      int* k_len, byte* k, int* c_len, byte* c);
bool kyber_kem_decaps(kyber_parameters& p, int kem_dk_len, byte* kem_dk,
      int c_len, byte* c, int* k_len, byte* k);
#endif

#if 0

class short_coefficient_vector {
public:
  int q_;
  int len_;

  short_coefficient_vector(int q, int len);
  ~short_coefficient_vector();

  vector<short int> c_;
};
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
short int read_ntt(vector<int> x, int m);
void write_ntt(int m, short int y, vector<int>* x);
#endif
