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
// File: tea.h

#include "cryptotypes.h"
#include "util.h"
#include "symmetric_cipher.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#ifndef _CRYPTO_TEA_H__
#define _CRYPTO_TEA_H__
using namespace std;

class Tea : public SymmetricCipher {
private:
  bool      initialized_;
  uint32_t  key_[4];

public:
  enum {
    BLOCKBYTESIZE= 16,
    MAXKB= (256/8),
    MAXKC= (256/32)
};
            Tea();
            ~Tea();

  bool      Init(int key_bit_size, byte* key, int direction);
  void      EncryptBlock(const byte* in, byte* out);
  void      DecryptBlock(const byte* in, byte* out);
  void      Encrypt(int size, byte* in, byte* out);
  void      Decrypt(int size, byte* in, byte* out);
};
#endif
