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
// File: ghash.h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <memory>

#include "cryptotypes.h"
#include "util.h"

#ifndef _CRYPTO_GHASH_H__
#define _CRYPTO_GHASH_H__

using std::string;

void Shift(int size_in, uint64_t* in, int shift, int size_out, uint64_t* out);
bool MultPoly(int size_a, uint64_t* a, int size_b, uint64_t* b,
              int size_c, uint64_t* c);
bool Reduce(int size_a, uint64_t* a, int size_p, uint64_t* min_poly);
bool MultAndReduce(int size_a, uint64_t* a, int size_b, uint64_t* b,
                   int size_p, uint64_t* min_poly, int size_c, uint64_t* c);

class Ghash {
public:
  enum {AUTH = 0, CIPHER = 1};
  Ghash();
  ~Ghash();

  void Init(byte* H);
  void AddAHash(int size, byte* data);
  void AddCHash(int size, byte* data);
  void FinalA();
  void FinalC();
  bool GetHash(uint64_t* out); 
  // test only
  void get_last_x(uint64_t* out);

private:
  bool finalized_A_;
  bool finalized_C_;
  uint64_t min_poly_[3];
  uint64_t H_[2];
  uint64_t bit_reversed_H_[2];
  uint64_t size_A_;
  uint64_t size_C_;
  uint64_t last_x_[2];
  int size_partial_;
  byte partial_[16];
  uint64_t digest_[2];

  void AddBlock(uint64_t* block);
  void AddToHash(int size, byte* data);
};
#endif
