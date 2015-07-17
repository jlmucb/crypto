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

bool MultPoly(int size_a, uint64_t* a, int size_b, uint64_t* b,
              int size_c, uint64_t* c) {
  return true;
}

bool Reduce(int size_a, uint64_t* a, int size_p, uint64_t* min_poly) {
  return true;
}

bool MultAndReduce(int size_a, uint64_t* a, int size_b, uint64_t* b,
                   int size_p, uint64_t* min_poly, int size_c, uint64_t* c) {
  return true;
}

Ghash::Ghash(uint64_t* H) {
  // x^7+x^2+x+1
  min_poly_[0] = 0x83;
  min_poly_[1] = 0x0;
  // x^128
  min_poly_[3] = 0x1;
  memcpy(H_, H, 16);
  memset(last_x_, 0, 32);
}

Ghash::~Ghash() {
}

void Ghash::Init() {
}

void Ghash::AddToHash(int size, byte* data) {
}

void Ghash::Final() {
}

bool Ghash::GetHash(uint64_t* out)  {
  return true;
}

