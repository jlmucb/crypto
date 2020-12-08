// Copyright 2020 John Manferdelli, All Rights Reserved.
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
// File: drng.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "crypto_names.h"
#include "drng.h"
#include "symmetric_cipher.h"
#include "aes.h"

ctr_drng_aes::ctr_drng_aes() {
  initialized_= false;
  reseed_ctr_ = 0;
  num_entropy_bits_ = 0;
  num_required_ent_bits_ = 0;
  current_size_pool_ = 0;
  pool_size_ = 0;
  memset(pool_, 0, MAXPOOL_SIZE);
  key_size_bytes_;
  block_size_bytes_ = aes::BLOCKBYTESIZE;
}

ctr_drng_aes::~ctr_drng_aes() {
}

void ctr_drng_aes::init_encrypt_key(byte* K) {
}

void ctr_drng_aes::encrypt_block(byte* block, byte* dest) {
}

void ctr_drng_aes::set_requirement(int n_ent, int n_pool_size) {
}

void ctr_drng_aes::add_entropy(int n, byte* bits) {
}

void ctr_drng_aes::init(int n_ent_bits, byte* ent_bits, int n_extra_bits, byte* extra_bits) {
}

void ctr_drng_aes::reseed(int n_ent_bits, byte* ent_bits, int n_extra_bits, byte* extra_bits) {
}

void ctr_drng_aes::update(int n, byte* data) {
}

bool ctr_drng_aes::generate(int num_bits_needed, int n_add_in_bits, byte* add_in_bits) {
  return true;
}

