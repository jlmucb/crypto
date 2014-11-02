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
// File: symmetric_cipher.h

#include "cryptotypes.h"
#include "util.h"
#include "keys.pb.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#ifndef _CRYPTO_SYMMETRIC_CIPHERS_H__
#define _CRYPTO_SYMMETRIC_CIPHERS_H__
using namespace std;

class SymmetricCipher {
public:
  enum {
    NONE= 0,
    ENCRYPT= 1,
    DECRYPT= 2,
    BOTH= 3
  };
  int       direction_;
  bool      initialized_;

  string*   cipher_name_;
  int       num_key_bits_;
  byte*     key_;

  SymmetricCipher();
  virtual ~SymmetricCipher();

  // direction: encrypt= 0, decrypt=
  virtual bool Init(int key_bit_size, byte* key_buf, int directionflag)= 0;
  virtual void Encrypt(int byte_size, byte* in, byte* out)= 0;
  virtual void Decrypt(int byte_size, byte* in, byte* out)= 0;

  bool SerializeSymmetricCipherToMessage(crypto_symmetric_key_message&);
  bool DeserializeSymmetricCipherFromMessage(crypto_symmetric_key_message&);
  void PrintSymmetricKey();
};

#endif

