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
// File: symmetric_cipher.h

#include "crypto_support.h"

#ifndef _CRYPTO_SYMMETRIC_CIPHERS_H__
#define _CRYPTO_SYMMETRIC_CIPHERS_H__

class symmetric_cipher {
 public:
  enum { NONE = 0, ENCRYPT = 1, DECRYPT = 2, BOTH = 3 };
  int direction_;
  bool initialized_;
  string algorithm_;
  int key_size_in_bits_;
  string secret_;
  byte* key_;

  symmetric_cipher();
  virtual ~symmetric_cipher();

  // direction: encrypt= 0, decrypt=
  virtual bool init(int key_bit_size, byte* key_buf, int directionflag) = 0;
  virtual void encrypt(int byte_size, byte* in, byte* out) = 0;
  virtual void decrypt(int byte_size, byte* in, byte* out) = 0;
};

#endif
