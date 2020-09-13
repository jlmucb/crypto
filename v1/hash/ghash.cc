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
// File: ghash.cc

#include "cryptotypes.h"
#include "util.h"
#include "conversions.h"
#include "ghash.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

const int uint64_bit_size = sizeof(uint64_t) * NBITSINBYTE;

int RealSize(int size, uint64_t* x) {
  for (int i = (size - 1); i >= 0; i--) {
    if (x[i] != 0ULL)
      return i + 1;
  }
  return 1;
}

bool BitOn(uint64_t* in, int pos) {
  int word_position = pos / uint64_bit_size;
  int bit_position = pos - word_position * uint64_bit_size;
  return (in[word_position] & (0x1ULL << bit_position)) != 0;
}

void Shift(int size_in, uint64_t* in, int shift, int size_out, uint64_t* out) {
  int word_shift = shift / uint64_bit_size;
  int bit_shift = shift - word_shift * uint64_bit_size;
  uint64_t bottom;
  uint64_t top;
  int top_shift;

  memset((byte*)out, 0, size_out * sizeof(uint64_t));
  for (int i = (size_in - 1); i >= 0; i--) {
    bottom = in[i] << bit_shift;
    top_shift = (sizeof(uint64_t) * NBITSINBYTE) - bit_shift;
    if (top_shift != (sizeof(uint64_t) * NBITSINBYTE))
      top = in[i] >> top_shift;
    else
      top = 0ULL;
    out[word_shift + i] |= bottom;
    if ((word_shift + i + 1) < size_out )
      out[word_shift + i + 1] |= top;
  }
}

bool XorPolyTo(int size_a, uint64_t* a, int size_b, uint64_t* b) {
  if (size_a != size_b)
    return false;
  for (int i = 0; i < size_a; i++)
    b[i] ^= a[i];
  return true;
}

bool MultPoly(int size_a, uint64_t* a, int size_b, uint64_t* b,
              int size_c, uint64_t* c) {
  if ((size_a + size_b) > 4)
    return false;
  if (size_c < 4)
    return false;

  uint64_t t[4] = {0ULL, 0ULL, 0ULL, 0ULL};
  uint64_t accum[4] = {0ULL, 0ULL, 0ULL, 0ULL};

  for (int j = (uint64_bit_size * size_b - 1) ; j >= 0; j--) {
    if (BitOn(b, j)) {
      Shift(size_a, a, j, 4, t);
      if (!XorPolyTo(4, t, 4, accum)) {
        return false;
      }
    }
  }
  int n = RealSize(4, accum);
  if (n > size_c)
    return false;
  for (int i = 0; i < n; i++)
    c[i] = accum[i];
  return true;
}

bool Reduce(int size_a, uint64_t* a, int size_p, uint64_t* min_poly) {
  uint64_t t[4] = {0ULL, 0ULL, 0ULL, 0ULL};

  if (RealSize(size_a, a) > 4 || size_a < 4 || RealSize(size_p, min_poly) > 4)
    return false;
  int top_bit_a = size_a * uint64_bit_size - 1;
  int top_bit_p = 128;
  int k;

  for (k = top_bit_a; k >= 0; k--) {
    if (BitOn(a, k))
      break;
    top_bit_a--;
  }

  for (k = top_bit_a; k >= 128; k--) {
    if (BitOn(a, k)) {
      Shift(size_p, min_poly, k - top_bit_p, 4, t);
      if (!XorPolyTo(4, t, size_a, a))
        return false;
    }
  }
  return true;
}

bool MultAndReduce(int size_a, uint64_t* a, int size_b, uint64_t* b,
                   int size_p, uint64_t* min_poly, int size_c, uint64_t* c) {
  uint64_t t[4] = {0ULL, 0ULL, 0ULL, 0ULL};

  if ((size_a + size_b) > 4)
    return false;

  if (!MultPoly(size_b, b, size_a, a, 4, t))
      return false;
  if (!Reduce(4, t, 3, min_poly))
    return false;

  memset((byte*)c, 0, sizeof(uint64_t) * size_c);
  for (int i = 0; i < RealSize(4, t); i++) 
    c[i] = t[i];
  return true;
}

void printPolyLR(int nbits, uint64_t* p) {
  for (int i = 0; i < nbits; i++) {
    if (BitOn(p, i)) {
      printf("x^%02d + ", i);
    }
  }
  printf("\n");
}

byte BitReverse(byte a) {
  return  ((a<<7) & 0x80) | ((a<<5) & 0x40) |
          ((a<<3) & 0x20) | ((a<<1) & 0x10) |
          ((a>>1) & 0x8) | ((a>>3) & 0x4) |
          ((a>>5) & 0x2) | ((a>>7) & 0x1);
}

bool bit_reverse_table_initialized = false;
byte bit_reverse_table[256];

void InitBitReverseTable() {
  for (int i = 0; i < 256; i++)
    bit_reverse_table[i] = BitReverse((byte)i);
  bit_reverse_table_initialized = true;
}

byte ReverseBitsInByte(byte a) {
  return bit_reverse_table[a];
}

void Transform(uint64_t* block) {
  uint64_t newblock[2];
  byte* p= (byte*)block;
  byte* q= (byte*)newblock;

  for (int i = 0; i < 16; i++) {
    *(q++) = ReverseBitsInByte(*(p++));
  }
  block[0] = newblock[0];
  block[1] = newblock[1];
}

Ghash::Ghash() {
  // x^128+x^7+x^2+x+1
  min_poly_[2] = 1ULL;
  min_poly_[1] = 0x0000000000000000ULL;
  min_poly_[0] = 0x87ULL;
  finalized_A_ = false;
  finalized_C_ = false;
  size_partial_ = 0;
  memset(partial_, 0, 16);
  last_x_[0] = 0ULL;
  last_x_[1] = 0ULL;
  digest_[0] = 0ULL;
  digest_[1] = 0ULL;
  H_[0] = 0ULL;
  H_[1] = 0ULL;
  size_A_ = 0ULL;
  size_C_ = 0ULL;
}

Ghash::~Ghash() {
  last_x_[0] = 0ULL;
  last_x_[1] = 0ULL;
  digest_[0] = 0ULL;
  digest_[1] = 0ULL;
  H_[0] = 0ULL;
  H_[1] = 0ULL;
}

void Ghash::Init(byte* H) {
  if (!bit_reverse_table_initialized)
    InitBitReverseTable();
    
  H_[0] = *((uint64_t*)&H[0]);
  H_[1] = *((uint64_t*)&H[8]);
  bit_reversed_H_[0] = H_[0];
  bit_reversed_H_[1] = H_[1];
  Transform(bit_reversed_H_);
  size_partial_ = 0;
  memset(partial_, 0, 16);
  last_x_[0] = 0ULL;
  last_x_[1] = 0ULL;
  digest_[0] = 0ULL;
  digest_[1] = 0ULL;
  size_A_ = 0ULL;
  size_C_ = 0ULL;
  finalized_A_ = false;
  finalized_C_ = false;
}

void Ghash::AddBlock(uint64_t* block) {
  uint64_t t[4] = {0ULL, 0ULL, 0ULL, 0ULL};

  for (int i = 0; i < 2; i++) 
    last_x_[i] ^= block[i];
  Transform(last_x_);
  if (!MultAndReduce(2, last_x_, 2, bit_reversed_H_, 3, min_poly_, 4, t))
    LOG(ERROR) << "GHash AddBlock failed at MultAndReduce";
  last_x_[1] = t[1];
  last_x_[0] = t[0];
  Transform(last_x_);
  Transform(H_);
}

void Ghash::AddToHash(int size, byte* data) {
  byte* next = data;
  uint64_t in[2];

  if (size_partial_ > 0) {
    if ((size_partial_ + size) >= 16) {
      int n = 16 - size_partial_;
      memcpy(&partial_[size_partial_], next, n);
      in[0] = *((uint64_t*)&partial_[0]);
      in[1] = *((uint64_t*)&partial_[8]);
      AddBlock(in);
      size_partial_ = 0;
      memset(partial_, 0, 16);
      next += n;
      size -= n;
    } else {
      memcpy(partial_, &partial_[size_partial_], size);
      size_partial_ += size;
      return;
    }
  }

  while (size >= 16) {
    in[0] = *((uint64_t*)&next[0]);
    in[1] = *((uint64_t*)&next[8]);
    AddBlock(in);
    next += 16;
    size -= 16;
  }
  if (size > 0) {
    memcpy(partial_, next, size);
    size_partial_ = size;
  }
}

void Ghash::AddAHash(int size, byte* data) {
  size_A_ += size*NBITSINBYTE;
  AddToHash(size, data);
}

void Ghash::AddCHash(int size, byte* data) {
  size_C_ += size*NBITSINBYTE;
  AddToHash(size, data);
}

void Ghash::FinalA() {
  uint64_t in[2];

  if (size_partial_ > 0) {
    in[0] = *((uint64_t*)&partial_[0]);
    in[1] = *((uint64_t*)&partial_[sizeof(uint64_t)]);
    AddBlock(in);
    size_partial_ = 0;
  }
  finalized_A_ = true;
}

void Ghash::FinalC() {
  uint64_t in[2];

  if (size_partial_ > 0) {
    memset(&partial_[size_partial_], 0, 16 - size_partial_);
    in[0] = *((uint64_t*)&partial_[0]);
    in[1] = *((uint64_t*)&partial_[sizeof(uint64_t)]);
    AddBlock(in);
    size_partial_ = 0;
  }
  ReverseCpy(sizeof(uint64_t), (byte*)&size_A_, (byte*)&in[0]);
  ReverseCpy(sizeof(uint64_t), (byte*)&size_C_, (byte*)&in[1]);
  AddBlock(in);
  digest_[1] = last_x_[1];
  digest_[0] = last_x_[0];
  finalized_C_ = true;
}

bool Ghash::GetHash(uint64_t* out)  {
  if (!finalized_C_)
    return false;
  out[0] = digest_[0];
  out[1] = digest_[1];
  return true;
}

void Ghash::get_last_x(uint64_t* out) {
  out[0] = last_x_[0];
  out[1] = last_x_[1];
}
