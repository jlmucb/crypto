// Copyright 2014-2020, John Manferdelli, All Rights Reserved.
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
// File: simonspeck.cc

#include "crypto_support.h"
#include "symmetric_cipher.h"
#include "simonspeck.h"

inline uint64_t left_rotate_64(uint64_t x, int r) {
  if (r < 0)
    r += 64;
  return (x << r) | (x >> (64 - r));
}

simon128::simon128() {
  initialized_ = false;
  algorithm_.assign("simon");
  size_ = 0;
}

simon128::~simon128() {
  memset((byte*)simon_key_, 0, sizeof(uint64_t) * 4);
  memset((byte*)round_key_, 0, sizeof(uint64_t) * 72);
  initialized_ = false;
}

static byte s_z2[64] = {1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0,
                        0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0,
                        1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1,
                        1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0};
/*
static byte s_z3[64] = {
  1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0,
  0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0,
  0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1,
  0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0
};
static byte s_z4[64] = {
  1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0,
  1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0,
  0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0,
  1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0
};
 */

uint64_t convert_to_64(byte* in) {
  uint64_t x = 0ULL;

  for (int i = 0; i < 64; i++) x = (x << 1) | in[i];
  return x;
}

uint64_t simon128::calculate_constants(int cn, int sn) {
  if (cn != 2 || sn > 61)
    return 0ULL;
  return (uint64_t)s_z2[sn];
}

bool simon128::calculate_ks() {
  int i;
  uint64_t t;

  if (size_ != 2)
    return false;

  for (i = 0; i < size_; i++)
    round_key_[i] = simon_key_[i];
  for (i = size_; i < num_rounds_; i++) {
    t = left_rotate_64(round_key_[i - 1], -3);
    if (size_ == 4) {
      t = t ^ round_key_[i - 3];
    }
    t = t ^ left_rotate_64(t, -1);
    round_key_[i] =
        (~round_key_[i - size_]) ^ t ^ calculate_constants(2, (i - size_) % 62) ^ 0x3ULL;
  }
  return true;
}

bool simon128::init(int key_bit_size, byte* key, int directionflag) {
  size_ = 0;
  key_size_in_bits_ = key_bit_size;
  secret_.assign((char*)key, key_size_in_bits_ / NBITSINBYTE);
  simon_key_[0] = *(uint64_t*)key;
  simon_key_[1] = *(uint64_t*)(key + sizeof(uint64_t));
  switch (key_bit_size) {
    case 128:
      size_ = 2;
      num_rounds_ = 68;
      memcpy((byte*)simon_key_, key, sizeof(uint64_t) * size_);
      break;
    case 192:
    case 256:
    default:
      return false;
  }
  if (!calculate_ks()) {
    initialized_ = false;
    return false;
  }
  initialized_ = true;
  direction_ = directionflag;
  return initialized_;
}

void simon128::encrypt_block(const byte* in, byte* out) {
  uint64_t x = *((uint64_t*)in);
  uint64_t y = *((uint64_t*)(in + sizeof(uint64_t)));
  uint64_t t;

  for (int i = 0; i < num_rounds_; i++) {
    t = x;
    x = y ^ (left_rotate_64(x, 1) & left_rotate_64(x, 8)) ^ left_rotate_64(x, 2) ^
        round_key_[i];
    y = t;
  }

  *((uint64_t*)out) = x;
  *((uint64_t*)(out + sizeof(uint64_t))) = y;
}

void simon128::decrypt_block(const byte* in, byte* out) {
  uint64_t x = *((uint64_t*)in);
  uint64_t y = *((uint64_t*)(in + sizeof(uint64_t)));
  uint64_t t;

  for (int i = (num_rounds_ - 1); i >= 0; i--) {
    t = y;
    y = x ^ (left_rotate_64(y, 1) & left_rotate_64(y, 8)) ^ left_rotate_64(y, 2) ^
        round_key_[i];
    x = t;
  }

  *((uint64_t*)out) = x;
  *((uint64_t*)(out + sizeof(uint64_t))) = y;
}

void simon128::encrypt(int size, byte* in, byte* out) {
  while (size > 0) {
    encrypt_block(in, out);
    size -= BLOCKBYTESIZE;
    in += BLOCKBYTESIZE;
    out += BLOCKBYTESIZE;
  }
}

void simon128::decrypt(int size, byte* in, byte* out) {
  while (size > 0) {
    decrypt_block(in, out);
    size -= BLOCKBYTESIZE;
    in += BLOCKBYTESIZE;
    out += BLOCKBYTESIZE;
  }
}
