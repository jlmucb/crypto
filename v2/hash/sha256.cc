//
// Copyright 2014 John Manferdelli, All Rights Reserved.
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
// File: sha256.cc

#include "crypto_support.h"
#include "hash.h"
#include "sha256.h"

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// Circular left shift in 32 bits
inline uint32_t rotlFixed(uint32_t x, uint32_t y) {
  return ((0xffffffffU) & (x << y)) | (((0xffffffffU) & x) >> (32 - y));
}
// Circular left shift in 32 bits
inline uint32_t rotrFixed(uint32_t x, uint32_t y) {
  return ((0xffffffffU) & (x >> y)) | (((0xffffffffU) & x) << (32 - y));
}

#define blk0(i) (W[i] = data[i])
#define blk1(i)           \
  (W[i & 15] = rotlFixed( \
       W[(i + 13) & 15] ^ W[(i + 8) & 15] ^ W[(i + 2) & 15] ^ W[i & 15], 1))
#define blk2(i) \
  (W[i & 15] += s1(W[(i - 2) & 15]) + W[(i - 7) & 15] + s0(W[(i - 15) & 15]))
#define Ch(x, y, z) (z ^ (x & (y ^ z)))
#define Maj(x, y, z) ((x & y) | (z & (x | y)))
#define a(i) T[(0 - i) & 7]
#define b(i) T[(1 - i) & 7]
#define c(i) T[(2 - i) & 7]
#define d(i) T[(3 - i) & 7]
#define e(i) T[(4 - i) & 7]
#define f(i) T[(5 - i) & 7]
#define g(i) T[(6 - i) & 7]
#define h(i) T[(7 - i) & 7]

#define S0(x) (rotrFixed(x, 2) ^ rotrFixed(x, 13) ^ rotrFixed(x, 22))
#define S1(x) (rotrFixed(x, 6) ^ rotrFixed(x, 11) ^ rotrFixed(x, 25))
#define s0(x) (rotrFixed(x, 7) ^ rotrFixed(x, 18) ^ (x >> 3))
#define s1(x) (rotrFixed(x, 17) ^ rotrFixed(x, 19) ^ (x >> 10))

#define R(i)                                                                \
  h(i) +=                                                                   \
      S1(e(i)) + Ch(e(i), f(i), g(i)) + K[i + j] + (j ? blk2(i) : blk0(i)); \
  d(i) += h(i);                                                             \
  h(i) += S0(a(i)) + Maj(a(i), b(i), c(i))

sha256::sha256() {
  num_bytes_waiting_ = 0;
  num_bits_processed_ = 0;
}

sha256::~sha256() {}

bool sha256::init() {
  num_bytes_waiting_ = 0;
  num_bits_processed_ = 0;
  hash_name_.assign("sha-256");
  finalized_ = false;
  memset(bytes_waiting_, 0, BLOCKBYTESIZE);
  memset(digest_, 0, DIGESTBYTESIZE);
  state_[0] = 0x6a09e667;
  state_[1] = 0xbb67ae85;
  state_[2] = 0x3c6ef372;
  state_[3] = 0xa54ff53a;
  state_[4] = 0x510e527f;
  state_[5] = 0x9b05688c;
  state_[6] = 0x1f83d9ab;
  state_[7] = 0x5be0cd19;
  return true;
}

void sha256::transform_block(const uint32_t* block) {
  uint32_t data[16];
  uint32_t W[16];
  uint32_t T[8];

#ifndef BIGENDIAN
  for (int i = 0; i < 16; i++)
    little_to_big_endian_32((uint32_t*)&block[i], &data[i]);
#else
  for (int i = 0; i < 16; i++) data[i] = block[i];
#endif
  for (int i = 0; i < 16; i++) W[i] = data[i];

  memcpy(T, state_, sizeof(T));
  for (unsigned int j = 0; j < 64; j += 16) {
    R(0);
    R(1);
    R(2);
    R(3);
    R(4);
    R(5);
    R(6);
    R(7);
    R(8);
    R(9);
    R(10);
    R(11);
    R(12);
    R(13);
    R(14);
    R(15);
  }
  state_[0] += a(0);
  state_[1] += b(0);
  state_[2] += c(0);
  state_[3] += d(0);
  state_[4] += e(0);
  state_[5] += f(0);
  state_[6] += g(0);
  state_[7] += h(0);
  memset(W, 0, sizeof(W));
  memset(T, 0, sizeof(T));
}

void sha256::add_to_hash(int size, const byte_t* in) {
  if (num_bytes_waiting_ > 0) {
    int needed = BLOCKBYTESIZE - num_bytes_waiting_;
    if (size < needed) {
      memcpy(&bytes_waiting_[num_bytes_waiting_], in, size);
      num_bytes_waiting_ += size;
      return;
    }
    memcpy(&bytes_waiting_[num_bytes_waiting_], in, needed);
    transform_block((const uint32_t*)bytes_waiting_);
    num_bits_processed_ += BLOCKBYTESIZE * NBITSINBYTE;
    size -= needed;
    in += needed;
    num_bytes_waiting_ = 0;
  }
  while (size >= BLOCKBYTESIZE) {
    transform_block((const uint32_t*)in);
    num_bits_processed_ += BLOCKBYTESIZE * NBITSINBYTE;
    size -= BLOCKBYTESIZE;
    in += BLOCKBYTESIZE;
  }
  if (size > 0) {
    num_bytes_waiting_ = size;
    memcpy(bytes_waiting_, in, size);
  }
}

bool sha256::get_digest(int size, byte_t* out) {
  if (!finalized_) return false;
  if (size < DIGESTBYTESIZE) return false;
  memcpy(out, digest_, DIGESTBYTESIZE);
  return true;
}

void sha256::finalize() {
  uint64_t num_bits = num_bits_processed_ + num_bytes_waiting_ * NBITSINBYTE;

  // append 1
  bytes_waiting_[num_bytes_waiting_++] = 0x80;
  if ((num_bytes_waiting_ + sizeof(uint64_t)) > BLOCKBYTESIZE) {
    memset(&bytes_waiting_[num_bytes_waiting_], 0,
           BLOCKBYTESIZE - num_bytes_waiting_);
    transform_block((const uint32_t*)bytes_waiting_);
    num_bytes_waiting_ = 0;
  }

  // zero and set bits processed
  memset(&bytes_waiting_[num_bytes_waiting_], 0,
         (BLOCKBYTESIZE - num_bytes_waiting_ - sizeof(uint64_t)));
  uint64_t* psize = (uint64_t*)&bytes_waiting_[BLOCKBYTESIZE - sizeof(uint64_t)];
#ifndef BIGENDIAN
  little_to_big_endian_64(&num_bits, psize);
#else
  *psize = num_bits;
#endif
  transform_block((const uint32_t*)bytes_waiting_);
  // 8 bytes of length (bit length)
  memcpy(digest_, (byte_t*)state_, DIGESTBYTESIZE);
  finalized_ = true;
}
