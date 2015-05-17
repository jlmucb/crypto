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
// File: aes.h

#include "cryptotypes.h"
#include "util.h"
#include "symmetric_cipher.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#ifndef _CRYPTO_AES_H__
#define _CRYPTO_AES_H__
using namespace std;

class Aes : public SymmetricCipher {
public:
  enum {
    MAXNR= 14,
    BLOCKBYTESIZE= 16,
    MAXKB= (256/8),
    MAXKC= (256/32)
  };

  uint32_t* encrypt_round_key_;
  uint32_t* decrypt_round_key_;
  int32_t   num_rounds_;

            Aes();
  virtual   ~Aes();

  bool      InitEnc();
  bool      InitDec();
  bool      Init(int key_bit_size, byte* key_buf, int directionflag);
  void      EncryptBlock(const byte* in, byte* out);
  void      DecryptBlock(const byte* in, byte* out);
  void      Encrypt(int byte_size, byte* in, byte* out);
  void      Decrypt(int byte_size, byte* in, byte* out);
};

class AesNi : public SymmetricCipher {
public:
  enum {
    MAXNR= 14,
    BLOCKBYTESIZE= 16,
    MAXKB= (256/8),
    MAXKC= (256/32)
};

  uint32_t* encrypt_round_key_;
  uint32_t* decrypt_round_key_;
  int32_t   num_rounds_;

            AesNi();
  virtual   ~AesNi();

  bool      InitEnc();
  bool      InitDec();
  bool      Init(int key_bit_size, byte* key_buf, int directionflag);
  void      EncryptBlock(const byte* in, byte* out);
  void      DecryptBlock(const byte* in, byte* out);
  void      Encrypt(int byte_size, byte* in, byte* out);
  void      Decrypt(int byte_size, byte* in, byte* out);
};

#endif

