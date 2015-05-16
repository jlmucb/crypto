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
// File: simonspeck.h

#include "cryptotypes.h"
#include "util.h"
#include "symmetric_cipher.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#ifndef _CRYPTO_SIMON_SPECK_H__
#define _CRYPTO_SIMON_SPECK_H__
using namespace std;

class Simon128 : public SymmetricCipher {
private:
  bool      initialized_;
  int       size_;
  uint64_t  key_[4];
  uint64_t  round_key_[72];
  int       num_rounds_;
  uint64_t  constants_[68];
  bool      CalculateKS();
  uint64_t  ConstCalc(int cn, int sn);

public:
  enum {
    BLOCKBYTESIZE= 16,
};
            Simon128();
  virtual   ~Simon128();

  bool      Init(int key_bit_size, byte* key, int directionflag);
  void      EncryptBlock(const byte* in, byte* out);
  void      DecryptBlock(const byte* in, byte* out);
  void      Encrypt(int size, byte* in, byte* out);
  void      Decrypt(int size, byte* in, byte* out);
};
#endif

