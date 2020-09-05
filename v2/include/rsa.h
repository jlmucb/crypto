//
// Copyright 2014 John Manferdelli, All Rights Reserved.
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
// File: rsa.h

#include "crypto_support.h"
#include "big_num.h"
#include <iostream>

#ifndef _CRYPTO_RSA_H__
#define _CRYPTO_RSA_H__
class rsa {
 public:
  bool initialized_;
  key_message *rsa_key_;
  int bit_size_modulus_;
  big_num* m_;
  big_num* e_;
  big_num* d_;
  big_num* p_;
  big_num* q_;
  big_num* dp_;
  big_num* dq_;
  big_num* m_prime_;
  big_num* p_prime_;
  big_num* q_prime_;
  string not_before_;
  string not_after_;
  int r_;

  rsa();
  ~rsa();

  bool compute_fast_decrypt_parameters();
  bool get_serialized_key_message(string* s);
  bool set_parameters_in_key_message();
  bool retrieve_parameters_from_key_message();
  bool extract_key_message_from_serialized(string& s);
  bool generate_rsa(int num_bits);
  bool make_rsa_key(const char* name, const char* purpose, double secondstolive);
  bool encrypt(int size_in, byte* in, int* size_out, byte* out, int speed);
  bool decrypt(int size_in, byte* in, int* size_out, byte* out, int speed);
  key_message* get_key() {return rsa_key_;}
};
#endif
