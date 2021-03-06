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
// File: sha3.h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <memory>

#include "cryptotypes.h"
#include "hash.h"

#ifndef _CRYPTO_SHA3__H
#define _CRYPTO_SHA3__H

class Sha3 : public CryptographicHash {
 public:
  enum {
    BLOCKBYTESIZE = 128,
    BLOCKBITSIZE = 1024,
    NR = 24,
    LANESIZEBITS = 64,
  };
  int num_out_bytes_;
  int num_bytes_waiting_;
  byte bytes_waiting_[BLOCKBYTESIZE];
  uint64_t state_[5 * 5];
  byte digest_[256];
  uint64_t num_bits_processed_;
  bool finalized_;

  Sha3(int num_bits);
  ~Sha3();

  void TransformBlock(const uint64_t*, int);

  bool Init();
  void AddToHash(int size, const byte* in);
  bool GetDigest(int size, byte* out);
  void Final();
};
#endif
