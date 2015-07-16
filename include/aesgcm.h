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
// File: aesgcm.h

#include "cryptotypes.h"
#include "util.h"
#include "symmetric_cipher.h"
#include "encryption_algorithm.h"
#include "aes.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>

#ifndef _CRYPTO_AESGCM_H__
#define _CRYPTO_AESGCM_H__
using namespace std;

class PolyGcmMult {
public:
  static uint64_t p_[3]; // = {0x87ULL, 0ULL, 1ULL};
  PolyGcmMult();
  ~PolyGcmMult();
  bool MultPoly(uint64_t* a, uint64_t* b, uint64_t* c);
  bool Reduce(uint64_t* a);
  bool MultAndReduce(uint64_t* a, uint64_t* b, uint64_t* c);
};

class AesGcm : public EncryptionAlgorithm {
 public:
  bool use_aesni_;

  Aes aes_obj_;
  AesNi aesni_obj_;
  byte iv_[32];
  byte ctr_blk_[Aes::BLOCKBYTESIZE];

  int num_unprocessed_input_bytes_;
  byte input_buf[Aes::BLOCKBYTESIZE];

  unsigned* ctr_;
  bool output_verified_;

  uint64_t last_Y_[4];

  AesGcm();
  ~AesGcm();

  void GHashInit(int size_H, uint64_t* H);
  void GHashAddBlock(uint64_t* X);
  void GHashAdd(int size, uint64_t* X);

  void GCtrInit(int size_key, uint64_t* key, int size_iv, uint64_t* iv);
  void GCtrAddBlock(uint64_t* X, uint64_t* Y);
  void GCtrAdd(uint64_t* X, uint64_t* Y, int size);

  bool Init(int size_key, byte*, int size_block,
            int size_tag, int size_A,
            int size_iv, byte* iv, bool use_aesni);

  void PrintEncryptionAlgorithm();

  void GcmEncryptBlock(byte* in, byte* out);
  void GcmDecryptBlock(byte* in, byte* out);

  bool AuthenticatedIn(int size_in, byte* in, int* size_out, byte* out);
  bool FinalAuthenticatedIn(int size_in, byte* in, int* size_out, byte* out);

  bool PlainIn(int size_in, byte* in, int* size_out, byte* out);
  bool CipherIn(int size_in, byte* in, int* size_out, byte* out);
  bool FinalPlainIn(int size_in, byte* in, int* size_out, byte* out);
  bool FinalCipherIn(int size_in, byte* in, int* size_out, byte* out);

  int DecryptInputQuantum();
  int EncryptInputQuantum();
  int MinimumFinalDecryptIn();
  int MinimumFinalEncryptIn();
  int MaxAdditionalOutput();
  int MaxAdditionalFinalOutput();
  bool ProcessInput(int size_in, byte* in, int* size_out, byte* out);
  bool ProcessFinalInput(int size_in, byte* in, int* size_out, byte* out);
  int InputBytesProcessed();
  int OutputBytesProduced();

  int GetComputedTag(int size, byte*);
  int GetReceivedTag(int size, byte*);
  bool MessageValid();

  bool GenerateScheme(const char* name, int num_bits);
  bool MakeScheme(const char* name, int num_key_bits,
                  byte* enc_key, byte* iv);
};

#endif
