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
// Project: New Cloudproxy Crypto
// File: sha1.cc

#include "cryptotypes.h"
#include <string>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "util.h"
#include "hash.h"
#include "sha1.h"

#define blk0(i) (W[i] = data[i])
#define blk1(i)           \
  (W[i & 15] = rotlFixed( \
       W[(i + 13) & 15] ^ W[(i + 8) & 15] ^ W[(i + 2) & 15] ^ W[i & 15], 1))
#define f1(x, y, z) (z ^ (x & (y ^ z)))
#define f2(x, y, z) (x ^ y ^ z)
#define f3(x, y, z) ((x & y) | (z & (x | y)))
#define f4(x, y, z) (x ^ y ^ z)

// Circular left shift in 32 bits
inline uint32_t rotlFixed(uint32_t x, uint32_t y) {
  return ((0xffffffffU) & (x << y)) | (((0xffffffffU) & x) >> (32 - y));
}

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v, w, x, y, z, i)                                 \
  z += f1(w, x, y) + blk0(i) + 0x5A827999 + rotlFixed(v, 5); \
  w = rotlFixed(w, 30);
#define R1(v, w, x, y, z, i)                                 \
  z += f1(w, x, y) + blk1(i) + 0x5A827999 + rotlFixed(v, 5); \
  w = rotlFixed(w, 30);
#define R2(v, w, x, y, z, i)                                 \
  z += f2(w, x, y) + blk1(i) + 0x6ED9EBA1 + rotlFixed(v, 5); \
  w = rotlFixed(w, 30);
#define R3(v, w, x, y, z, i)                                 \
  z += f3(w, x, y) + blk1(i) + 0x8F1BBCDC + rotlFixed(v, 5); \
  w = rotlFixed(w, 30);
#define R4(v, w, x, y, z, i)                                 \
  z += f4(w, x, y) + blk1(i) + 0xCA62C1D6 + rotlFixed(v, 5); \
  w = rotlFixed(w, 30);

Sha1::Sha1() {
  num_bytes_waiting_ = 0;
  num_bits_processed_ = 0;
}

Sha1::~Sha1() {}

bool Sha1::Init() {
  if (hash_name_ == nullptr) {
    hash_name_ = new string("sha-1");
  }
  num_bytes_waiting_ = 0;
  finalized_ = false;
  memset(bytes_waiting_, 0, BLOCKBYTESIZE);
  memset(digest_, 0, DIGESTBYTESIZE);
  state_[0] = 0x67452301L;
  state_[1] = 0xEFCDAB89L;
  state_[2] = 0x98BADCFEL;
  state_[3] = 0x10325476L;
  state_[4] = 0xC3D2E1F0L;
  return true;
}

void Sha1::TransformBlock(const uint32_t* block) {
  uint32_t data[16];
  uint32_t W[16];
  uint32_t a = state_[0];
  uint32_t b = state_[1];
  uint32_t c = state_[2];
  uint32_t d = state_[3];
  uint32_t e = state_[4];

#ifndef BIGENDIAN
  LittleEndian32(16, block, data);
#else
  for (int i = 0; i < 16; i++) data[i] = block[i];
#endif
  for (int i = 0; i < 16; i++) W[i] = data[i];

  R0(a, b, c, d, e, 0);
  R0(e, a, b, c, d, 1);
  R0(d, e, a, b, c, 2);
  R0(c, d, e, a, b, 3);
  R0(b, c, d, e, a, 4);
  R0(a, b, c, d, e, 5);
  R0(e, a, b, c, d, 6);
  R0(d, e, a, b, c, 7);
  R0(c, d, e, a, b, 8);
  R0(b, c, d, e, a, 9);
  R0(a, b, c, d, e, 10);
  R0(e, a, b, c, d, 11);
  R0(d, e, a, b, c, 12);
  R0(c, d, e, a, b, 13);
  R0(b, c, d, e, a, 14);
  R0(a, b, c, d, e, 15);
  R1(e, a, b, c, d, 16);
  R1(d, e, a, b, c, 17);
  R1(c, d, e, a, b, 18);
  R1(b, c, d, e, a, 19);
  R2(a, b, c, d, e, 20);
  R2(e, a, b, c, d, 21);
  R2(d, e, a, b, c, 22);
  R2(c, d, e, a, b, 23);
  R2(b, c, d, e, a, 24);
  R2(a, b, c, d, e, 25);
  R2(e, a, b, c, d, 26);
  R2(d, e, a, b, c, 27);
  R2(c, d, e, a, b, 28);
  R2(b, c, d, e, a, 29);
  R2(a, b, c, d, e, 30);
  R2(e, a, b, c, d, 31);
  R2(d, e, a, b, c, 32);
  R2(c, d, e, a, b, 33);
  R2(b, c, d, e, a, 34);
  R2(a, b, c, d, e, 35);
  R2(e, a, b, c, d, 36);
  R2(d, e, a, b, c, 37);
  R2(c, d, e, a, b, 38);
  R2(b, c, d, e, a, 39);
  R3(a, b, c, d, e, 40);
  R3(e, a, b, c, d, 41);
  R3(d, e, a, b, c, 42);
  R3(c, d, e, a, b, 43);
  R3(b, c, d, e, a, 44);
  R3(a, b, c, d, e, 45);
  R3(e, a, b, c, d, 46);
  R3(d, e, a, b, c, 47);
  R3(c, d, e, a, b, 48);
  R3(b, c, d, e, a, 49);
  R3(a, b, c, d, e, 50);
  R3(e, a, b, c, d, 51);
  R3(d, e, a, b, c, 52);
  R3(c, d, e, a, b, 53);
  R3(b, c, d, e, a, 54);
  R3(a, b, c, d, e, 55);
  R3(e, a, b, c, d, 56);
  R3(d, e, a, b, c, 57);
  R3(c, d, e, a, b, 58);
  R3(b, c, d, e, a, 59);
  R4(a, b, c, d, e, 60);
  R4(e, a, b, c, d, 61);
  R4(d, e, a, b, c, 62);
  R4(c, d, e, a, b, 63);
  R4(b, c, d, e, a, 64);
  R4(a, b, c, d, e, 65);
  R4(e, a, b, c, d, 66);
  R4(d, e, a, b, c, 67);
  R4(c, d, e, a, b, 68);
  R4(b, c, d, e, a, 69);
  R4(a, b, c, d, e, 70);
  R4(e, a, b, c, d, 71);
  R4(d, e, a, b, c, 72);
  R4(c, d, e, a, b, 73);
  R4(b, c, d, e, a, 74);
  R4(a, b, c, d, e, 75);
  R4(e, a, b, c, d, 76);
  R4(d, e, a, b, c, 77);
  R4(c, d, e, a, b, 78);
  R4(b, c, d, e, a, 79);

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
}

void Sha1::AddToHash(int size, const byte* in) {
  if (num_bytes_waiting_ > 0) {
    int needed = BLOCKBYTESIZE - num_bytes_waiting_;
    if (size < needed) {
      memcpy(&bytes_waiting_[num_bytes_waiting_], in, size);
      num_bytes_waiting_ += size;
      return;
    }
    memcpy(&bytes_waiting_[num_bytes_waiting_], in, needed);
    TransformBlock((const uint32_t*)bytes_waiting_);
    num_bits_processed_ += BLOCKBYTESIZE * NBITSINBYTE;
    size -= needed;
    in += needed;
    num_bytes_waiting_ = 0;
  }
  while (size >= BLOCKBYTESIZE) {
    TransformBlock((const uint32_t*)in);
    num_bits_processed_ += BLOCKBYTESIZE * NBITSINBYTE;
    size -= BLOCKBYTESIZE;
    in += BLOCKBYTESIZE;
  }
  if (size > 0) {
    num_bytes_waiting_ = size;
    memcpy(bytes_waiting_, in, size);
  }
}

bool Sha1::GetDigest(int size, byte* out) {
  if (!finalized_) return false;
  if (size < DIGESTBYTESIZE) return false;
  memcpy(out, digest_, DIGESTBYTESIZE);
  return true;
}

void Sha1::Final() {
  uint64_t num_bits = num_bits_processed_ + num_bytes_waiting_ * NBITSINBYTE;

  // append 1
  bytes_waiting_[num_bytes_waiting_++] = 0x80;
  if ((num_bytes_waiting_ + sizeof(uint64_t)) > BLOCKBYTESIZE) {
    memset(&bytes_waiting_[num_bytes_waiting_], 0,
           BLOCKBYTESIZE - num_bytes_waiting_);
    TransformBlock((const uint32_t*)bytes_waiting_);
    num_bytes_waiting_ = 0;
  }

  // zero and set bits processed
  memset(&bytes_waiting_[num_bytes_waiting_], 0,
         (BLOCKBYTESIZE - num_bytes_waiting_ - sizeof(uint64_t)));
#ifndef BIGENDIAN
  uint32_t* psize =
      (uint32_t*)&bytes_waiting_[BLOCKBYTESIZE - sizeof(uint64_t)];
  LittleEndian32(1, (uint32_t*)&num_bits, psize + 1);
  LittleEndian32(1, ((uint32_t*)&num_bits) + 1, psize);
#else
  uint64_t* psize =
      (uint64_t*)&bytes_waiting_[BLOCKBYTESIZE - sizeof(uint64_t)];
  *psize = num_bits;
#endif
  TransformBlock((const uint32_t*)bytes_waiting_);
  // 8 bytes of length (bit length)
  memcpy(digest_, (byte*)state_, DIGESTBYTESIZE);
  finalized_ = true;
}
