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
// File: encryption_scheme.h

#ifndef _CRYPTO_ENCRYPTION_SCHEME_CIPHERS_H__
#define _CRYPTO_ENCRYPTION_SCHEME_CIPHERS_H__

#include "crypto_support.h"
#include "aes.h"
#include "hmac_sha256.h"
#include "big_num.h"

class encryption_scheme {
public:
  enum { NONE = 0, AES= 0x01, SHA2 = 0x01, SYMMETRIC_PAD = 0x01, MODE = 0x01, CTR = 1, CBC = 2 };
  enum { ENCRYPT=1, DECRYPT=2};
  enum { MAXBLOCKSIZE=64};
  bool initialized_;

  scheme_message* scheme_msg_;
  int   mode_;
  int   pad_;

  bool  nonce_data_valid_;
  string initial_nonce_;
  string running_nonce_;
  big_num* counter_nonce_;

  int operation_;
  int total_message_size_;
  int encrypted_bytes_output_;
  int total_bytes_output_;

  int block_size_;
  int hmac_digest_size_;
  int hmac_block_size_;

  bool message_valid_;

  aes enc_obj_;
  hmac_sha256 int_obj_;

  bool get_message_valid();
  bool message_info(int msg_size, int operation);
  int get_block_size();
  int get_mac_size();
  int get_bytes_encrypted();
  int get_total_bytes_output();
  int get_message_size();

  void clear();
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

  void ctr_encrypt_step(byte* in, byte* out);
  void ctr_decrypt_step(byte* in, byte* out);
  void cbc_encrypt_step(byte* in, byte* out);
  void cbc_decrypt_step(byte* in, byte* out);
  void update_nonce(int size, byte* buf);
  bool get_nonce_data(int size_in, byte* in);

  bool encrypt_block(int size_in, byte* in, byte* out);
  bool decrypt_block(int size_in, byte* in, byte* out);

  bool finalize_encrypt(int size_final, byte* final_in, int* size_out, byte* out);
  bool finalize_decrypt(int size_final, byte* final_in,
        int* size_out, byte* out, byte* computed_mac);

  bool encrypt_message(int size_in, byte* in, int size_out, byte* out);
  bool decrypt_message(int size_in, byte* in, int size_out, byte* out);
};

#endif
