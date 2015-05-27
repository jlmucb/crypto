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
// File: rc4.cc

#include "cryptotypes.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "rc4.h"

inline void swap(byte* a, byte* b) {
  byte c = *a;
  *a = *b;
  *b = c;
}

Rc4::Rc4() { initialized_ = false; }

Rc4::~Rc4() { initialized_ = false; }

bool Rc4::Init(int size, byte* key) {
  int i;

  for (i = 0; i < 256; i++) state_[i] = i;

  key_size_ = size;
  for (i = 0; i < 256; i++) {
    key_[i] = key[i % size];
  }

  index2_ = 0;
  for (index1_ = 0; index1_ < 256; index1_++) {
    index2_ = (key_[index1_] + state_[index1_] + index2_) % 256;
    swap(&state_[index1_], &state_[index2_]);
  }
  index1_ = 0;
  index2_ = 0;
  initialized_ = true;
  return true;
}

byte Rc4::Next() {
  index1_ = (index1_ + 1) % 256;
  index2_ = (index2_ + state_[index1_]) % 256;
  swap(&state_[index1_], &state_[index2_]);
  return state_[(state_[index1_] + state_[index2_]) % 256];
}

void Rc4::Encrypt(int size, byte* in, byte* out) {
  int i;

  for (i = 0; i < size; i++) out[i] = in[i] ^ Next();
}
