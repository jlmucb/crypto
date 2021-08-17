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
#include "hmac_sha256.h"
#include "hmac_drng.h"

// Note:  Mixers assume big endian so reverse bytes should
// be invoked before and after any call to the addition stuff.
// size_n1 >= size_n2

hmac_drng::hmac_drng() {
  initialized_= false;
  reseed_ctr_ = 0;
  current_entropy_ = 0;
}

hmac_drng::~hmac_drng() {
  initialized_= false;
  reseed_ctr_ = 0;
  current_entropy_ = 0;
  memset(K_, 0, 64);
  memset(V_, 0, 64);
}

double hmac_drng::current_entropy() {
  return current_entropy_;
}

bool hmac_drng::update(int size_data, byte* data) {
  hmac_sha256 h;
  int buf_size = h.MACBYTESIZE + 1 + size_data;
  byte buf[buf_size];
  memset(buf, 0, buf_size);

  if (!h.init(h.MACBYTESIZE, K_))
    return false;
  int n = 0;
  memcpy(&buf[n], V_, h.MACBYTESIZE);
  n += h.MACBYTESIZE;
  buf[n++] = 0;
  memcpy(&buf[n], data, size_data);
  h.add_to_inner_hash(buf_size, buf);
  h.finalize();
  h.get_hmac(h.MACBYTESIZE, K_);

  if (!h.init(h.MACBYTESIZE, K_))
    return false;
  h.add_to_inner_hash(h.MACBYTESIZE, V_);
  h.finalize();
  h.get_hmac(h.MACBYTESIZE, V_);

  if (size_data > 0) {
    memcpy(buf, V_, h.MACBYTESIZE);
    buf[h.MACBYTESIZE] = 1;

    h.init(h.MACBYTESIZE, K_);
    h.add_to_inner_hash(buf_size, buf);
    h.finalize();
    h.get_hmac(h.MACBYTESIZE, V_);
  }
  return true;
}

bool hmac_drng::init(int size_nonce, byte* nonce, int size_personalization,
      byte* personalization, int entropy_width, byte* material, double ent) {
  reseed_ctr_ = 0;
  int seed_material_size = entropy_width + size_nonce + size_personalization;

  byte seed_material[seed_material_size];
  memset(seed_material, 0, seed_material_size);

  int  n = 0;
  memcpy(seed_material, material, entropy_width);
  n += entropy_width;
  memcpy(&seed_material[n], nonce, size_nonce);
  n += size_nonce; 
  memcpy(&seed_material[n], personalization, size_personalization);

  memset(K_, 0, 64);
  memset(V_, 0, 64);
  for (int i = 0; i < 32; i++)
    V_[i] = 0x01;

  if (!hmac_drng::update(0, nullptr))
    return -1;
  current_entropy_ = ent;
  reseed_ctr_ = 1;
  initialized_= true;
  return initialized_;
}

bool hmac_drng::generate(int num_bytes_needed, byte* out, int size_add_in_bytes,
            byte* add_in_bytes) {
  hmac_sha256 h;

  update(size_add_in_bytes, add_in_bytes);
  int n = 0;
  int k = 0;
  while (n < num_bytes_needed) {
    if (!h.init(h.MACBYTESIZE, K_))
      return false;
    h.add_to_inner_hash(h.MACBYTESIZE, V_);
    h.finalize();
    h.get_hmac(h.MACBYTESIZE, V_);
    if ((num_bytes_needed - n) >= h.MACBYTESIZE)
      k = h.MACBYTESIZE;
    else
      k = num_bytes_needed - n;
    memcpy(&out[n], V_, k);
    n += k; 
  }
  return true;
}
