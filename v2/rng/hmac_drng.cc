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
// File: hmac_drng.cc

#include <stdio.h>
#include "crypto_support.h"
#include "probability_support.h"
#include "hmac_drng.h"

// Note:  Mixers assume big endian so reverse bytes should
// be invoked before and after any call to the addition stuff.
// size_n1 >= size_n2

hmac_drng::hmac_drng() {
  initialized_= false;
  reseed_ctr_ = 0;
  hash_byte_output_size_ = sha256::DIGESTBYTESIZE;
  seed_len_bits_ = 440;  // we're using sha256
  seed_len_bytes_ = seed_len_bits_ / NBITSINBYTE;;
  current_entropy_ = 0;
}

hmac_drng::~hmac_drng() {
  initialized_= false;
  reseed_ctr_ = 0;
  current_entropy_ = 0;
  memset(C_, 0, 64);
  memset(V_, 0, 64);
}

double hmac_drng::current_entropy() {
  return current_entropy_;
}

// K= HMAC(K,V||0x00||data)
// V = HMAC(K, V)
// if data
//    K= HMAC(K, V || 0x01||data);
//    V = HMAC(K, V)
bool hmac_drng::update(int size_data, byte* data) {
  return true;
}

// seed= entropy || nonce || personailzation
// K = 0
// V = 0101...01
// K = Update(seed)
bool hmac_drng::init(int size_nonce, byte* nonce, int size_personalization,
      byte* personalization, int entropy_width, byte* material, double ent) {
  reseed_ctr_ = 0;
  int seed_material_size = entropy_width + size_nonce + size_personalization;

  byte seed_material[seed_material_size];
  memset(seed_material, 0, seed_material_size);
  memcpy(seed_material, material, entropy_width);
  hash_df(seed_material_size, seed_material, seed_len_bits_, V_);
  memset(seed_material, 0, seed_material_size);
  memcpy(&seed_material[1], V_, seed_len_bytes_);
  hash_df(seed_len_bytes_ + 1, seed_material, seed_len_bits_, C_);
  current_entropy_ = ent;
  reseed_ctr_ = 1;
  initialized_= true;
  return initialized_;
}

// Update(data)
// t = empty
// while (|t| < l) {
//    V= HMAC(K,V)
//    t = t || V
// Update(data)
// return bits
bool hmac_drng::generate(int num_bits_needed, byte* out, int size_add_in_bits,
            byte* add_in_bits) {
  return true;
}
