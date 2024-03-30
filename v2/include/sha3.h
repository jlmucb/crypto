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
// File: sha3.h

#include "crypto_support.h"
#include "hash.h"

#ifndef _CRYPTO_SHA3__H
#define _CRYPTO_SHA3__H

class sha3 : public crypto_hash {
 public:
  enum {
    BLOCKBYTESIZE = 128,
    BLOCKBITSIZE = 1024,
    NR = 24,
    LANESIZEBITS = 64,
    DIGESTBYTESIZE = 128,
  };
  int c_;
  int r_;
  int num_out_bytes_;
  int num_bytes_waiting_;
  byte bytes_waiting_[BLOCKBYTESIZE];
  uint64_t state_[5 * 5];  // 1600 bits
  byte digest_[sha3::DIGESTBYTESIZE];
  uint64_t num_bits_processed_;
  bool finalized_;

  sha3();
  ~sha3();

  void transform_block(const uint64_t*, int);

  bool init(int c, int num_bytes_out);
  void add_to_hash(int size, const byte* in);
  bool get_digest(int size, byte* out);
  void finalize();
  void shake_finalize();
};
#endif
