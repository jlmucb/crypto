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

#include "cryptotypes.h"
#include "util.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>

#ifndef _CRYPTO_GHASH_H__
#define _CRYPTO_GHASH_H__

bool MultPoly(int size_a, uint64_t* a, int size_b, uint64_t* b,
              int size_c, uint64_t* c);
bool Reduce(int size_a, uint64_t* a, int size_p, uint64_t* min_poly);
bool MultAndReduce(int size_a, uint64_t* a, int size_b, uint64_t* b,
                   int size_p, uint64_t* min_poly, int size_c, uint64_t* c);

class Ghash {
public:
  Ghash(uint64_t* H);
  ~Ghash();

  void Init();
  void AddToHash(int size, byte* data);
  void Final();
  bool GetHash(uint64_t* out); 

private:
  uint64_t min_poly_[4];
  uint64_t H_[4];
  uint64_t last_x_[4];
};

class GAesCtr {
public:
  GAesCtr();
  ~GAesCtr();

  void Init(int size_iv, uint64_t* iv, int size_K, byte* K);
  void NextBlock(uint64_t* in, uint64_t* out);

private:
  bool use_aesni_;
  Aes aes_;
  AesNi aesni_;
  uint64_t  last_ctr_[2];
  uint32_t* ctr_;
};

#endif
