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
#include "aes.h"

const int MAXPOOL_SIZE = 512;

class ctr_drng_aes {
private:
  int reseed_ctr_;
  int num_entropy_bits_;
  int num_required_ent_bits_;
  byte pool_[MAXPOOL_SIZE];

  aes cipher;
  void init_encrypt_key(byte* K);
  void encrypt_block(byte* block, byte* dest);
public:
  ctr_drng_aes::ctr_drng_aes();
  ctr_drng_aes::~ctr_drng_aes();

  void add_entropy(int n, byte* bits);:w
  void init(int n_ent_bits, byte* ent_bits, int n_extra_bits, byte* extra_bits);
  void reseed(int n_ent_bits, byte* ent_bits, int n_extra_bits, byte* extra_bits);
  void update(int n, byte* data);
  bool generate(int num_bits_needed, int n_add_in_bits, byte* add_in_bits);
};
#endif


