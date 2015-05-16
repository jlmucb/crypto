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
// File: simonspeck.cc

#include "cryptotypes.h"
#include "util.h"
#include "symmetric_cipher.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "simonspeck.h"

inline uint64_t leftRotate64(uint64_t x, int r) {
  if (r<0)
    r+= 64;
  return (x<<r)|(x>>(64-r));
}

Simon128::Simon128() {
  initialized_= false;
  size_= 0;
}

Simon128::~Simon128() {
  memset((byte*)key_, 0, sizeof(uint64_t)*4);
  memset((byte*)round_key_, 0, sizeof(uint64_t)*72);
  initialized_= false;
}

static byte s_z2[64] = {
  1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0,
  0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0,
  1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1,
  1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0
};
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

uint64_t  ConvertTo64(byte* in) {
  uint64_t  x= 0ULL;

  for (int i= 0; i<64; i++)
    x= (x<<1)|in[i];
  return x;
}

uint64_t Simon128::ConstCalc(int cn, int sn) {
  if(cn!=2 || sn>61)
    return 0ULL;
  return (uint64_t)s_z2[sn];
}

bool Simon128::CalculateKS() {
  int       i;
  uint64_t  t;

  if(size_!=2)
    return false;

  for (i= 0; i<size_; i++)
    round_key_[i]= key_[i];
  for (i= size_; i<num_rounds_; i++) {
    t= leftRotate64(round_key_[i-1], -3);
    if (size_==4) {
      t= t^round_key_[i-3];
    }
    t= t^leftRotate64(t,-1);
    round_key_[i]= (~round_key_[i-size_])^t^ConstCalc(2, (i-size_)%62)^0x3ULL;
  }
#if 0
  printf("\nRound keys:\n");
  for (i= 0; i<num_rounds_; i++)
    printf("%02d %016llx\n", i, round_key_[i]);
  printf("\n");
#endif
  return true;
}

bool Simon128::Init(int key_bit_size, byte* key, int directionflag) {
  size_= 0;
  switch(key_bit_size) {
    case 128:
      size_= 2;
      num_rounds_= 68;
      memcpy((byte*)key_, key, sizeof(uint64_t)*size_);
      break;
    case 192:
    case 256:
    default:
      return false;
  }
  if(!CalculateKS()) {
    initialized_= false;
    return false;
  }
  initialized_= true;
  return true;
}

void Simon128::EncryptBlock(const byte* in, byte* out) {
  uint64_t  x= *((uint64_t*)in);
  uint64_t  y= *((uint64_t*)(in+sizeof(uint64_t)));
  uint64_t  t;

  for (int i= 0; i<num_rounds_; i++) {
    t= x;
    x= y^(leftRotate64(x,1)&leftRotate64(x,8))^leftRotate64(x,2)^round_key_[i];
    y= t;
  }

  *((uint64_t*)out)= x;
  *((uint64_t*)(out+sizeof(uint64_t)))= y;
}

void Simon128::DecryptBlock(const byte* in, byte* out) {
  uint64_t  x= *((uint64_t*)in);
  uint64_t  y= *((uint64_t*)(in+sizeof(uint64_t)));
  uint64_t  t;

  for (int i= (num_rounds_-1); i>=0; i--) {
    t= y;
    y= x^(leftRotate64(y,1)&leftRotate64(y,8))^leftRotate64(y,2)^round_key_[i];
    x= t;
  }

  *((uint64_t*)out)= x;
  *((uint64_t*)(out+sizeof(uint64_t)))= y;
}

void Simon128::Encrypt(int size, byte* in, byte* out) {
  while(size>0) {
    EncryptBlock(in, out);
    size-= BLOCKBYTESIZE;
    in+= BLOCKBYTESIZE;
    out+= BLOCKBYTESIZE;
  }
}

void Simon128::Decrypt(int size, byte* in, byte* out) {
  while(size>0) {
    DecryptBlock(in, out);
    size-= BLOCKBYTESIZE;
    in+= BLOCKBYTESIZE;
    out+= BLOCKBYTESIZE;
  }
}
