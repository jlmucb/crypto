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
// File: symmetric_cipher.cc

#include "crypto_support.h"
#include "aes.h"
#include "symmetric_cipher.h"

symmetric_cipher::symmetric_cipher() {
  direction_ = NONE;
  initialized_ = false;
  key_ = nullptr;
}

symmetric_cipher::~symmetric_cipher() {
  initialized_ = false;
  secret_.clear();
  key_ = nullptr;
}

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

bool encryption_scheme::init(const char* mode, const char* pad,
      const char* enc_alg, int size_enc_key, byte* enc_key,
      const char* hmac_alg, int size_hmac_key, byte* hmac_key,
      int size_nonce, byte* nonce) {
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

bool encryption_scheme::finalize(int size_final, byte* final_in, int* size_out, byte* out) {
  return true;
}


