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
// File: cmac.h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <memory>

#include "cryptotypes.h"
#include "hash.h"
#include "aes.h"

#ifndef _CRYPTO_CMAC__H
#define _CRYPTO_CMAC__H

class Cmac : public CryptographicHash {
 public:
  enum {
    BLOCKBITSIZE = 128,
    BLOCKBYTESIZE = 16,
  };
private:
  const byte R_[16]= {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x87,
    };
  int num_out_bytes_;
  int num_bytes_waiting_;
  byte bytes_waiting_[BLOCKBYTESIZE];
  byte K1_[16];
  byte K2_[16];
  byte state_[16];
  byte digest_[16];
  uint64_t num_bits_processed_;
  bool finalized_;
  Aes aes_;

  bool ComputeSubKeys(byte* K);

public:
  Cmac(int num_bits);
  ~Cmac();

  byte* getK1() {return K1_;};
  byte* getK2() {return K2_;};

  bool Init(byte* K);
  void AddToHash(int size, const byte* in);
  bool GetDigest(int size, byte* out);
  void Final(int size, byte* in);
};
#endif
