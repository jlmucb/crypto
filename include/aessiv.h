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
// File: aessiv.h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <memory>

#include "cryptotypes.h"
#include "util.h"
#include "symmetric_cipher.h"
#include "encryption_algorithm.h"
#include "aes.h"
#include "sha256.h"
#include "cmac.h"

#ifndef _CRYPTO_AESSIV_H__
#define _CRYPTO_AESSIV_H__

using std::string;

class AesSiv {
private:
  const byte R_[16]= {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x87,
    };
  bool initialized_;
  Aes aes_;
  byte iv_[32];
  byte ctr_blk_[Aes::BLOCKBYTESIZE];
  int num_unprocessed_input_bytes_;
  byte K1_[16];
  byte K2_[16];

 public:

  AesSiv();
  ~AesSiv();

  bool ComputeSubKeys(byte* K);
  bool Encrypt(byte* K, int hdr_size, byte* hdr,
               int msg_size, byte* msg, int* size_out, byte* out);
  bool Decrypt(byte* K, int hdr_size, byte* hdr,
               int msg_size, byte* msg, int* size_out, byte* out);

  bool GenerateScheme(const char* name, int num_bits);
  bool MakeScheme(const char* name, int num_bits, byte* enc_key, byte* int_key,
                  byte* nonce, byte* iv);
};

#endif
