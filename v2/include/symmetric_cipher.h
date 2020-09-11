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
// File: symmetric_cipher.h

#include "crypto_support.h"

#ifndef _CRYPTO_SYMMETRIC_CIPHERS_H__
#define _CRYPTO_SYMMETRIC_CIPHERS_H__

class symmetric_cipher {
 public:
  enum { NONE = 0, ENCRYPT = 1, DECRYPT = 2, BOTH = 3 };
  int direction_;
  bool initialized_;
  string algorithm_;
  int key_size_in_bits_;
  string secret_;
  byte* key_;

  symmetric_cipher();
  virtual ~symmetric_cipher();

  // direction: encrypt= 0, decrypt=
  virtual bool init(int key_bit_size, byte* key_buf, int directionflag) = 0;
  virtual void encrypt(int byte_size, byte* in, byte* out) = 0;
  virtual void decrypt(int byte_size, byte* in, byte* out) = 0;
};

class encryption_scheme {
public:
  enum { NONE = 0, AES= 0x0001, SHA2 = 0x0001, SYMMETRIC_PAD = 0x0001 };
  bool initialized_;

  scheme_message scheme_msg_;
  string iv_;
  int   mode_;
  int   pad_;

  bool  nonce_data_valid_;
  byte* running_nonce_;
  int block_size_;
  int hmac_size_;
  int encrypted_bytes_output_;
  int total_bytes_output_;

  symmetric_cipher* enc_obj_;
  // should really do inheritance for alg.
  void* hmac_obj_;
  void* pad_obj_;

  int get_block_size();
  int get_bytes_encrypted();
  int get_total_bytes_output();
  bool get_message_valid();

  encryption_scheme();
  ~encryption_scheme();

  bool recover_encryption_scheme_from_message(string& s);
  bool get_encryption_scheme_message(string* s);

  bool init(const char* alg, const char* id_name,
      const char* mode, const char* pad, const char* purpose,
      const char* not_before, const char* not_after,
      const char* enc_alg, int size_enc_key, string& enc_key,
      const char* enc_key_name, const char* hmac_alg,
      int size_hmac_key,  string& hmac_key, int size_nonce,
      string& nonce);

  bool get_nonce_data(int size_in, byte* in);

  bool encrypt_block(int size_in, byte* in, byte* out);
  bool decrypt_block(int size_in, byte* in, byte* out);

  bool finalize_encrypt(int size_final, byte* final_in, int* size_out, byte* out);
  bool finalize_decrypt(int size_final, byte* final_in, int* size_out, byte* out);

  bool message_valid_;
};

#endif
