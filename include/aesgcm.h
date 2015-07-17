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

bool MultPoly(int size_a, uint64_t* a, int size_b, uint64_t* b,
              int size_c, uint64_t* c);
bool Reduce(int size_a, uint64_t* a, int size_p, uint64_t* min_poly);
bool MultAndReduce(int size_a, uint64_t* a, int size_b, uint64_t* b,
                   int size_p, uint64_t* min_poly, int size_c, uint64_t* c);

class Ghash {
public:
  Ghash(uint64_t* H);
  ~Ghash();

  void Init();
  void AddToHash(int size, byte* data);
  void Final();
  bool GetHash(uint64_t* out); 

private:
  uint64_t min_poly_[4];
  uint64_t H_[4];
  uint64_t last_x_[4];
};

class GAesCtr {
public:
  GAesCtr();
  ~GAesCtr();

  void Init(int size_iv, uint64_t* iv, int size_K, byte* K);
  void NextBlock(uint64_t* in, uint64_t* out);

private:
  bool use_aesni_;
  Aes aes_;
  AesNi aesni_;
  uint64_t  last_ctr_[2];
  uint32_t* ctr_;
};

class AesGcm : public EncryptionAlgorithm {
 public:
  bool use_aesni_;

  Aes aes_obj_;
  AesNi aesni_obj_;
  byte ctr_blk_[Aes::BLOCKBYTESIZE];

  int num_unprocessed_input_bytes_;
  byte input_buf[Aes::BLOCKBYTESIZE];

  bool output_verified_;
  int block_size_;

  int size_A_;
  int size_C_;

  unsigned* ctr_;
  uint64_t last_CB_[4];

  uint64_t last_Y_[4];
  int size_H;
  uint64_t H_[4];
  int size_iv_;
  uint64_t iv_[4];
  int size_key_;
  uint64_t key_[4];

  AesGcm();
  ~AesGcm();

  bool Init(int size_key, byte*, int size_block, int size_tag,
            int size_A, int size_C, int size_iv, byte* iv, bool use_aesni);
  void PrintEncryptionAlgorithm();

  int GetComputedTag(int size, byte*);
  int GetReceivedTag(int size, byte*);

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

  bool MessageValid();

  bool GenerateScheme(const char* name, int num_bits);
  bool MakeScheme(const char* name, int num_key_bits,
                  byte* key, byte* iv);
};

#endif
