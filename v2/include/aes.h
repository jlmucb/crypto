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
// File: aes.h

#ifndef _CRYPTO_AES_H__
#define _CRYPTO_AES_H__

#include "crypto_support.h"
#include "symmetric_cipher.h"

class aes : public symmetric_cipher {
 public:
  enum {
    MAXNR = 14,
    BLOCKBYTESIZE = 16,
    MAXKB = (256 / 8),
    MAXKC = (256 / 32)
  };

  uint32_t* encrypt_round_key_;
  uint32_t* decrypt_round_key_;
  int32_t num_rounds_;

  aes();
  virtual ~aes();

  bool init_encrypt();
  bool init_decrypt();
  bool init(int key_bit_size, byte_t* key_buf, int directionflag);
  void encrypt_block(const byte_t* in, byte_t* out);
  void decrypt_block(const byte_t* in, byte_t* out);
  void encrypt(int byte_size, byte_t* in, byte_t* out);
  void decrypt(int byte_size, byte_t* in, byte_t* out);
};

class aesni : public symmetric_cipher {
 public:
  enum {
    MAXNR = 14,
    BLOCKBYTESIZE = 16,
    MAXKB = (256 / 8),
    MAXKC = (256 / 32)
  };

  uint32_t* encrypt_round_key_;
  uint32_t* decrypt_round_key_;
  int32_t num_rounds_;

  aesni();
  virtual ~aesni();

  bool init_encrypt();
  bool init_decrypt();
  bool init(int key_bit_size, byte_t* key_buf, int directionflag);
  void encrypt_block(const byte_t* in, byte_t* out);
  void decrypt_block(const byte_t* in, byte_t* out);
  void encrypt(int byte_size, byte_t* in, byte_t* out);
  void decrypt(int byte_size, byte_t* in, byte_t* out);
};

#endif
