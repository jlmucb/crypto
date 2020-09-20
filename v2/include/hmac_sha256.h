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
// File: hmac_sha256.h

#include "crypto_support.h"
#include "hash.h"
#include "sha256.h"

#ifndef _CRYPTO_HMAC_SHA256_H__
#define _CRYPTO_HMAC_SHA256_H__

class hmac_sha256 {
 public:
  enum { BLOCKBYTESIZE = 64, MACBYTESIZE = 32 };

  bool macvalid_;
  byte key_[BLOCKBYTESIZE];
  byte mac_[MACBYTESIZE];
  sha256 inner_sha256_;

  hmac_sha256();
  ~hmac_sha256();

  bool init(int size, byte* key);
  void add_to_inner_hash(int size, byte* in);
  bool get_hmac(int size, byte* out);
  void finalize();
};
#endif
