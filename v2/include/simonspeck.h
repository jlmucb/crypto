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
// File: simonspeck.h

#include "crypto_support.h"
#include "symmetric_cipher.h"

#ifndef _CRYPTO_SIMON_SPECK_H__
#define _CRYPTO_SIMON_SPECK_H__

class simon128 : public symmetric_cipher {
 private:
  bool initialized_;
  int size_;
  uint64_t key_[4];
  uint64_t round_key_[72];
  int num_rounds_;
  bool calculate_ks();
  uint64_t calculate_constants(int cn, int sn);

 public:
  enum {
    BLOCKBYTESIZE = 16,
  };
  simon128();
  virtual ~simon128();

  bool init(int key_bit_size, byte* key, int directionflag);
  void encrypt_block(const byte* in, byte* out);
  void decrypt_block(const byte* in, byte* out);
  void encrypt(int size, byte* in, byte* out);
  void decrypt(int size, byte* in, byte* out);
};
#endif
