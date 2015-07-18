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
#include <string>
#include <stdio.h>
#include <stdlib.h>

const int uint64_bit_size = sizeof(uint64_t) * NBITSINBYTE;

bool BitOn(uint64_t* in, int pos) {
  int word_position = pos / uint64_bit_size;
  int bit_position = pos - word_position*uint64_bit_size;

  return (in[word_position] & (0x1 >> bit_position)) != 0;
}

void Shift(int size_in, uint64_t* in, int shift, int size_out, uint64_t* out) {
  int word_shift = shift / uint64_bit_size;
  int bit_shift = shift - word_shift * uint64_bit_size;

  uint64_t bottom;
  uint64_t top;
  for (int i = 0; i < size_in; i++) {
    bottom = in[i] >> bit_shift;
    top = in[i] << (sizeof(uint64_t) * NBITSINBYTE - bit_shift);
    out[word_shift + i] |= bottom;
    out[word_shift + i + 1] |= top;
  }
}

void XorPolyTo(int size_a, uint64_t* a, int size_b, uint64_t* b) {
  for (int i = 0; i < size_a; i++)
    b[i] |= a[i];
}

bool MultPoly(int size_a, uint64_t* a, int size_b, uint64_t* b,
              int size_c, uint64_t* c) {
  if ((size_a + size_b) > 4)
    return false;
  if (size_c < 4)
    return false;

  uint64_t t[8];
  uint64_t accum[8];

  memset(accum, 0, sizeof(uint64_t) * 8);
  memset(c, 0, sizeof(uint64_t) * size_c);
  memset(t, 0, sizeof(uint64_t) * 8);

  for (int i = 0; i < size_a; i++) {
    for (int j = 0; j< (uint64_bit_size * size_b); j++) {
      if (BitOn(b, j)) {
        Shift(size_a, a, j, 8, t);
        XorPolyTo(size_c, t, size_c, accum);
      }
    }
  }
  return true;
}

bool Reduce(int size_a, uint64_t* a, int size_p, uint64_t* min_poly) {
  uint64_t t[8];

  int top_bit_a = size_a * uint64_bit_size - 1;
  int top_bit_p = size_p * uint64_bit_size - 1;
  int k;

  for (k = top_bit_p; k >= 128; k--) {
    if (BitOn(min_poly, k))
      top_bit_p--;
    else
      break;
  }
  for (k = top_bit_a; k >= 256; k--) {
    if (BitOn(a, k))
      top_bit_a--;
    else
      break;
  }

  for (k = top_bit_a; k >= top_bit_p; k--) {
    memset(t, 0, sizeof(uint64_t) * 8);
    if (BitOn(a, k)) {
    Shift(size_p, min_poly, k - top_bit_p, 8, t);
    XorPolyTo(8, t, size_a, a);
    }
  }
  return true;
}

bool MultAndReduce(int size_a, uint64_t* a, int size_b, uint64_t* b,
                   int size_p, uint64_t* min_poly, int size_c, uint64_t* c) {
  uint64_t t[8];
  memset(t, 0, sizeof(uint64_t) * 8);
  if (!MultPoly(size_a, a, size_b, b, size_c, c))
      return false;
  if (!Reduce(4, t, 3, min_poly))
    return false;
  memcpy(c, t, 4 * sizeof(uint64_t));
  return true;
}

Ghash::Ghash() {
  // x^7+x^2+x+1
  min_poly_[0] = 0x83;
  min_poly_[1] = 0x0;
  // x^128
  min_poly_[2] = 0x1;
  uint64_t zero[2] = {0ULL, 0ULL};
  Init(zero);
}

Ghash::~Ghash() {
  memset(H_, 0, 32);
  memset(last_x_, 0, 32);
  memset(digest_, 0, 64);
}

void Ghash::Init(uint64_t* H) {
  memcpy(H_, H, 16);
  finalized_A_ = false;
  finalized_C_ = false;
  size_partial_ = 0;
  memset(partial_, 0, 64);
  memset(last_x_, 0, 64);
  memset(digest_, 0, 64);
  size_A_ = 0;
  size_C_ = 0;
}

void Ghash::AddBlock(uint64_t* block) {
  uint64_t t[2];
  
  for (int i = 0; i < 2; i++) 
    last_x_[i] ^= block[i];
  MultAndReduce(16, last_x_, 16, H_, 48, min_poly_, 16, t);
  memcpy(last_x_, t, 32);
}

void Ghash::AddToHash(int size, byte* data) {
  byte* next = data;

  if (size_partial_ > 0) {
    if ((size_partial_+size) >= 16) {
      int n = 16 - size_partial_;
      memcpy(next, &partial_[size_partial_], n);
      AddBlock((uint64_t*)partial_);
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
    AddBlock((uint64_t*)next);
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
  if (size_partial_ > 0) {
    AddBlock((uint64_t*)partial_);
    size_partial_ = 0;
  }
  finalized_A_ = true;
}

void Ghash::FinalC() {
  if (size_partial_ > 0) {
    AddBlock((uint64_t*)partial_);
    size_partial_ = 0;
  }
  memset(partial_, 0, 16);
  uint64_t* count = (uint64_t*) partial_;
  *count = size_A_;
  *(++count) = size_C_;
  AddBlock((uint64_t*)partial_);
  memcpy(digest_, last_x_, 16);
  finalized_C_ = true;
}

bool Ghash::GetHash(byte* out)  {
  if (!finalized_C_)
    return false;
  memcpy(out, (byte*)digest_, 16);
  return true;
}

