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
  num_entropy_bits_present_ = 0;
  num_ent_bits_required_ = 0;
  current_size_pool_ = 0;
  pool_size_ = 0;
  memset(pool_, 0, MAXPOOL_SIZE);
  key_size_bytes_;
  block_size_bytes_ = aes::BLOCKBYTESIZE;
  reseed_interval_ = 100;
}

ctr_drng_aes::~ctr_drng_aes() {
  initialized_= false;
  reseed_ctr_ = 0;
  num_entropy_bits_present_ = 0;
  num_ent_bits_required_ = 0;
  current_size_pool_ = 0;
  pool_size_ = 0;
  memset(pool_, 0, MAXPOOL_SIZE);
  memset(current_K_, 0, 64);
  memset(current_V_, 0, 64);
  key_size_bytes_ = aes::BLOCKBYTESIZE;
  block_size_bytes_ = aes::BLOCKBYTESIZE;
}

void ctr_drng_aes::init_encrypt_key(byte* K) {
}

void ctr_drng_aes::encrypt_block(byte* block, byte* dest) {
}

void ctr_drng_aes::set_requirement(int n_ent, int n_pool_size) {
  num_ent_bits_required_ = n_ent;
  pool_size_ = n_pool_size;
}

void ctr_drng_aes::add_entropy(int n, byte* bits, int ent) {
}

int ctr_drng_aes::entropy_estimate() {
  return num_entropy_bits_present_;
}

bool ctr_drng_aes::init(int n_ent_bits, byte* ent_bits,
      int n_extra_bits, byte* extra_bits, int ent) {
  reseed_ctr_ = 0;
  if (num_ent_bits_required_ < num_entropy_bits_present_)
    return false;
  num_entropy_bits_present_ += ent;
  // pool_ || ent_bits
  // seed_bits = pool_ ^ extra_bits
  current_size_pool_;
  pool_size_;
  pool_; 
  initialized_= true;
  // K = 0
  // V = 0
  // Update(pool_size_, pool_);
  reseed_ctr_ = 1;
  // while (len(temp) < seed_len)
  //    V= V+1
  //    out = encrypt_block(K, V);
  //    temp = temp || out
  // K = Left(key_size_bytes_, temp)
  // V = Right(block_size_bytes_, temp)
  return initialized_;
}

bool ctr_drng_aes::reseed(int n_ent_bits, byte* ent_bits, int n_extra_bits, byte* extra_bits) {
}

void ctr_drng_aes::update(int n, byte* data) {
  // temp = empty
  // while len(temp) < seed_len)
  //    V= V+1
  //    out = encrypt_block(V)
  //    temp = temp || out
  //  temp ^= data
  // temp = Left(key_size_bytes_, temp)
  // V = Right(block_size_bytes_, temp)
}

bool ctr_drng_aes::generate(int num_bits_needed, int n_add_in_bits, byte* add_in_bits) {
  // if (reseed_ctr_ >= reseed_interval_)
  //    reseed
  // fill add_in_bits to seed_len with 0's
  // Update(add_in_bits)
  // temp = empty
  //  while (len(temp) < num_bits_needed)
  //    V+= 1
  //    out= encrypt_block(V)
  //    temp = temp || out
  //    return Left num_bits_needed of temp
  // Update(add_in_bits
  // reseed_ctr++
  return true;
}

