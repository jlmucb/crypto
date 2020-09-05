//
// Copyright 2014 John Manferdelli, All r_ptights r_pteserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// or in the the file LICENSE-2.0.txt in the top level sourcedirectory
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WAr_ptr_ptANTIES Or_pt CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
// File: ecc.h

#include "crypto_support.h"
#include "big_num.h"
#include "big_num_functions.h"
#include "ecc.h"

#ifndef _CRYPTO_ECC_H__
#define _CRYPTO_ECC_H__

class curve_point {
 public:
  big_num* x_;
  big_num* y_;
  big_num* z_;

  curve_point();
  curve_point(int size);
  curve_point(big_num& x, big_num& y);
  curve_point(curve_point& pt);
  curve_point(curve_point& pt, int capacity);
  ~curve_point();

  bool is_zero();
  void clear();
  void make_zero();
  bool copy_from(curve_point& pt);
  bool copy_to(curve_point& pt);
  bool normalize(big_num& p);
  void print();
};

class ecc_curve {
 public:
  int modulus_bit_size_;
  big_num* a_;
  big_num* b_;
  big_num* p_;

  ecc_curve();
  ecc_curve(int size);
  ecc_curve(big_num& a, big_num& b, big_num& p);
  ~ecc_curve();

  void clear();
  void print_curve();
};

class ecc {
 public:
  bool initialized_;
  key_message *ecc_key_;
  int prime_bit_size_;
  big_num* p_;
  string not_before_;
  string not_after_;
  curve_point base_point_;
  string secret_;
  
  ecc();
  ~ecc(); 

  bool get_serialized_key_message(string* s);
  bool set_parameters_in_key_message();
  bool retrieve_parameters_from_key_message();
  bool extract_key_message_from_serialized(string& s);
  bool generate_ecc(int num_bits);
  bool decrypt(curve_point& pt1, curve_point& pt2, int* size, byte* plain);
  bool make_ecc_key(const char* name, const char* usage, const char* owner,
         double secondstolive);
  bool generate_ecc(string& curve_name, const char* name, const char* usage,
                    const char* owner, double seconds_to_live);
  bool encrypt(int size, byte* plain, big_num& k, curve_point& pt1,
                     curve_point& pt2);
  void print();
};

bool init_ecc_curves();
bool ecc_embed(ecc_curve& c, big_num& m, curve_point& pt, int shift, int trys);
bool ecc_extract(ecc_curve& c, curve_point& pt, big_num& m, int shift);
bool ecc_normalize(ecc_curve& c, curve_point& pt);
bool ecc_add(ecc_curve& c, curve_point& pt, curve_point& q_pt, curve_point& r_pt);
bool ecc_sub(ecc_curve& c, curve_point& pt, curve_point& q_pt, curve_point& r_pt);
bool ecc_double(ecc_curve& c, curve_point& pt, curve_point& r_pt);
bool ecc_mult(ecc_curve& c, curve_point& pt, big_num& x, curve_point& r_pt);
bool faster_ecc_mult(ecc_curve& c, curve_point& pt, big_num& x, curve_point& r_pt);
bool projective_to_affine(ecc_curve& c, curve_point& pt);
bool projective_add(ecc_curve& c, curve_point& pt, curve_point& q_pt, curve_point& r_pt);
bool projective_double(ecc_curve& c, curve_point& pt, curve_point& r_pt);
bool projective_point_multult(ecc_curve& c, big_num& x, curve_point& pt, curve_point& r_pt);
ec/big_num/big_num/g

#endif
