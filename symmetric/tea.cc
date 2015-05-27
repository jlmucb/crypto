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
// File: tea.cc

#include "cryptotypes.h"
#include "util.h"
#include "symmetric_cipher.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "tea.h"

Tea::Tea() { initialized_ = false; }

Tea::~Tea() {}

bool Tea::Init(int key_bit_size, byte* key, int direction) {
  if (key_bit_size != 64)
    return false;
  uint32_t* kp = (uint32_t*)key;
  for (int i = 0; i < 4; i++) key_[i] = kp[i];
  initialized_ = true;
  return true;
}

void Tea::EncryptBlock(const byte* in, byte* out) {
  uint32_t* ip = (uint32_t*)in;
  uint32_t* op = (uint32_t*)out;
  uint32_t v0 = ip[0];
  uint32_t v1 = ip[1];
  uint32_t sum = 0;
  uint32_t i;
  uint32_t delta = 0x9e3779b9;
  uint32_t k0 = key_[0];
  uint32_t k1 = key_[1];
  uint32_t k2 = key_[2];
  uint32_t k3 = key_[3];

  for (i = 0; i < 32; i++) {
    sum += delta;
    v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
    v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
  }
  op[0] = v0;
  op[1] = v1;
}

void Tea::DecryptBlock(const byte* in, byte* out) {
  uint32_t* ip = (uint32_t*)in;
  uint32_t* op = (uint32_t*)out;
  uint32_t v0 = ip[0];
  uint32_t v1 = ip[1];
  uint32_t sum = 0xC6EF3720;
  uint32_t i;
  uint32_t delta = 0x9e3779b9;
  uint32_t k0 = key_[0];
  uint32_t k1 = key_[1];
  uint32_t k2 = key_[2];
  uint32_t k3 = key_[3];

  for (i = 0; i < 32; i++) {
    v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
    sum -= delta;
  }
  op[0] = v0;
  op[1] = v1;
}

void Tea::Encrypt(int size, byte* in, byte* out) {
  while (size > 0) {
    EncryptBlock(in, out);
    size -= 8;
    in += 8;
    out += 8;
  }
}

void Tea::Decrypt(int size, byte* in, byte* out) {
  while (size > 0) {
    DecryptBlock(in, out);
    size -= 8;
    in += 8;
    out += 8;
  }
}
