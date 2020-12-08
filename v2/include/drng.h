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
// File: drng.h

#ifndef _CRYPTO_DRNG_H__
#define _CRYPTO_DRNG_H__
#include "crypto_support.h"
#include "symmetric_cipher.h"
#include "aes.h"


class ctr_drng_aes {
  enum {MAXPOOL_SIZE = 512};
private:
  bool initialized_;
  int reseed_ctr_;
  int reseed_interval_;
  int num_entropy_bits_present_;
  int num_ent_bits_required_;
  int current_size_pool_;
  int pool_size_;
  byte pool_[MAXPOOL_SIZE];
  byte current_K_[64];
  byte current_V_[64];

  int key_size_bytes_;
  int block_size_bytes_;
  aes cipher;
  void init_encrypt_key(byte* K);
  void encrypt_block(byte* block, byte* dest);
public:
  ctr_drng_aes();
  ~ctr_drng_aes();

  int entropy_estimate();
  void set_requirement(int n_ent, int n_pool_size);
  void add_entropy(int n, byte* bits, int ent);
  bool init(int n_ent_bits, byte* ent_bits, int n_extra_bits, byte* extra_bits, int ent);
  bool reseed(int n_ent_bits, byte* ent_bits, int n_extra_bits, byte* extra_bits);
  void update(int n, byte* data);
  bool generate(int num_bits_needed, int n_add_in_bits, byte* add_in_bits);
};
#endif


