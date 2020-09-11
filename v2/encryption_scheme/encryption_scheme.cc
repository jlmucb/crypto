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
#include "encryption_scheme.h"
#include "big_num.h"
#include "big_num_functions.h"

void encryption_scheme::update_nonce() {
  if (mode_ == CTR) {
    big_unsigned_add_to(*counter_nonce_, big_one);
    running_nonce_.assign((char*)counter_nonce_->value_ptr(), block_size_);
    return;
  }
  if (mode_ == CBC) {
    return;
  }
}

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
  initialized_ = false;
  scheme_msg_ = nullptr;
  initial_nonce_.clear();
  mode_ = encryption_scheme::NONE;
  pad_= encryption_scheme::NONE;
  nonce_data_valid_ = false;
  running_nonce_.clear();
  counter_nonce_ = new big_num(10);
  counter_nonce_->zero_num();
  encrypted_bytes_output_ = 0;
  total_bytes_output_ = 0;
  block_size_ = 0;
  hmac_block_size_ = 0;
  hmac_digest_size_ = 0;
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
        const char* not_before, const char* not_after, const char* enc_alg,
        int size_enc_key, string& enc_key, const char* enc_key_name,
        const char* hmac_alg, int size_hmac_key,  string& hmac_key,
        int size_nonce, string& nonce) {

  if (alg == nullptr)
    return false;

   // NONE = 0, AES= 0x01, SHA2 = 0x01, SYMMETRIC_PAD = 0x01, MODE = 0x01
  if (pad == nullptr)
    return false;
  if (strcmp(pad, "sym-pad") == 0)
    pad_ = SYMMETRIC_PAD;
  else
    return false;

  if (mode == nullptr)
    return false;
  if (strcmp(mode, "sym-pad") == 0)
    mode_ = SYMMETRIC_PAD;
  else
    return false;

  if (strcmp(enc_alg, "aes") == 0) {
    if (!enc_obj_.init(size_enc_key, (byte*)enc_key.data(), aes::BOTH))
      return false;
    block_size_ = aes::BLOCKBYTESIZE;
  } else {
    return false;
  }

  if (strcmp(hmac_alg, "hmac-sha256") == 0) {
    if (!int_obj_.init(size_hmac_key, (byte*)hmac_key.data()))
      return false;
    hmac_digest_size_ = sha256::DIGESTBYTESIZE;
    hmac_block_size_ = sha256::BLOCKBYTESIZE;
  } else {
    return false;
  }

  initial_nonce_.clear();
  initial_nonce_.assign(nonce.data(), size_nonce);
  running_nonce_.clear();
  running_nonce_.assign(nonce.data(), size_nonce);
  counter_nonce_->zero_num();
  memcpy(counter_nonce_->value_ptr(), (byte*)nonce.data(), size_nonce);
  counter_nonce_->normalize();
  nonce_data_valid_ = true;

  encrypted_bytes_output_ = 0;
  total_bytes_output_ = 0;

  scheme_msg_ = make_scheme(alg, id_name, mode, pad, purpose,
      not_before, not_after, enc_alg, size_enc_key, enc_key,
      enc_key_name, hmac_alg, size_hmac_key,  hmac_key, size_nonce, nonce);
  if (scheme_msg_ == nullptr)
    return false;
  return true;
}

bool encryption_scheme::get_nonce_data(int size_in, byte* in) {
  return true;
}

bool encryption_scheme::encrypt_block(int size_in, byte* in, byte* out) {
  update_nonce();
  return true;
}

bool encryption_scheme::decrypt_block(int size_in, byte* in, byte* out) {
  update_nonce();
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
  if (*size_out < hmac_digest_size_)
    return false;
  // bool get_hmac(hmac_digest_size_, out);
  total_bytes_output_ += hmac_digest_size_;

  return true;
}

bool encryption_scheme::finalize_decrypt(int size_final, byte* final_in,
      int* size_out, byte* out) {
  return true;
}

