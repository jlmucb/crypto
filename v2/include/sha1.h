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

#include "crypto_support.h"
#include "hash.h"

#ifndef _CRYPTO_SHA1_H__
#define _CRYPTO_SHA1_H__

class sha1 : public crypto_hash {
 public:
  enum { BLOCKBYTESIZE = 64, DIGESTBYTESIZE = 20 };

  int num_bytes_waiting_;
  byte bytes_waiting_[BLOCKBYTESIZE];
  uint32_t state_[DIGESTBYTESIZE / sizeof(uint32_t)];
  byte digest_[DIGESTBYTESIZE];
  uint64_t num_bits_processed_;

  sha1();
  ~sha1();

  void transform_block(const uint32_t* data);

  bool init();
  void add_to_hash(int size, const byte* in);
  bool get_digest(int size, byte* out);
  void finalize();
};
#endif
