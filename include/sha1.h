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
// File: sha1.h

#include "cryptotypes.h"
#include "hash.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#ifndef _CRYPTO_SHA1_H__
#define _CRYPTO_SHA1_H__
using namespace std;

class Sha1 : public CryptographicHash {
public:
  enum {
    BLOCKBYTESIZE= 64,
    DIGESTBYTESIZE= 20
};

  int       num_bytes_waiting_;
  byte      bytes_waiting_[BLOCKBYTESIZE];
  uint32_t  state_[DIGESTBYTESIZE/sizeof(uint32_t)];
  byte      digest_[DIGESTBYTESIZE];
  uint64_t  num_bits_processed_;

  Sha1();
  ~Sha1();

  void      TransformBlock(const uint32_t* data);

  bool      Init();
  void      AddToHash(int size, const byte* in);
  bool      GetDigest(int size, byte* out);
  void      Final();
};
#endif

