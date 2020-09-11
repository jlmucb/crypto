//
// Copyright 2020 John Manferdelli, All Rights Reserved.
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
// File: encryption_scheme.cc

#include "crypto_support.h"
#include "symmetric_cipher.h"
#include "aes.h"
#include "hash.h"
#include "sha256.h"
#include "hmac_sha256.h"

/*
   encryption_scheme
    enum { NONE = 0, AES= 0x0001, SHA2 = 0x0001, SYMMETRIC_PAD = 0x0001 };
    bool initialized_;
    scheme_message scheme_msg_;
    string iv_;
    int   mode_;
    int   pad_;
    bool  nonce_data_valid_;
    byte* running_nonce_;
    int block_size_;
    int encrypted_bytes_output_;
    int total_bytes_output_;
    symmetric_cipher* enc_obj_;
    void* hmac_obj_;
    void* pad_obj_;
    bool message_valid_;
*/

int encryption_scheme::get_block_size() {
  return 0;
}

int encryption_scheme::get_bytes_encrypted() {
  return 0;
}

int encryption_scheme::get_total_bytes_output() {
  return 0;
}

bool encryption_scheme::get_message_valid() {
  return true;
}

encryption_scheme::encryption_scheme() {
}

encryption_scheme::~encryption_scheme() {
}

bool encryption_scheme::recover_encryption_scheme_from_message(string& s) {
  return true;
}

bool encryption_scheme::get_encryption_scheme_message(string* s) {
  return true;
}

bool encryption_scheme::encryption_scheme::init(const char* alg, const char* id_name,
      const char* mode, const char* pad, const char* purpose,
      const char* not_before, const char* not_after,
      const char* enc_alg, int size_enc_key, string& enc_key,
      const char* enc_key_name, const char* hmac_alg,
      int size_hmac_key,  string& hmac_key,
      int size_nonce, string& nonce) {
  return true;
}

bool encryption_scheme::get_nonce_data(int size_in, byte* in) {
  return true;
}

bool encryption_scheme::encrypt_block(int size_in, byte* in, byte* out) {
  return true;
}

bool encryption_scheme::decrypt_block(int size_in, byte* in, byte* out) {
  return true;
}

bool encryption_scheme::finalize_encrypt(int size_final, byte* final_in,
      int* size_out, byte* out) {

  // pad final block
  byte final_block_1[128];
  byte final_block_2[128];
  int n = size_final;
  if (size_final > 0) {
    memcpy(final_block_1, final_in, n);
  }
  if (n >= block_size_) {
    // encrypt_block(int size_in, byte* in, byte* out);
    n = 0;
  }
  final_block_1[n++] = 0x80;
  memset(&final_block_1[n], 0, block_size_ - n);
  // encrypt_block(int size_in, byte* in, byte* out);

  // finalize and append hmac
  // void finalize();
  if (*size_out < hmac_size_)
    return false;
  // bool get_hmac(hmac_size_, out);
  total_bytes_output_ += hmac_size_;

  return true;
}

bool encryption_scheme::finalize_decrypt(int size_final, byte* final_in,
      int* size_out, byte* out) {
  return true;
}

