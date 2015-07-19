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
#include "ghash.h"
#include "aes.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>

#ifndef _CRYPTO_AESGCM_H__
#define _CRYPTO_AESGCM_H__
using namespace std;

class GAesCtr {

private:
  int direction_;
  bool use_aesni_;
  Aes aes_;
  AesNi aesni_;
  byte partial_[16];
  int  size_partial_;
  uint64_t last_ctr_[2];
  uint64_t* ctr_;

public:
  GAesCtr();
  ~GAesCtr();

  bool Init(int size_iv, byte* iv, int bit_size_K, byte* K,
            int direction, bool use_aesni);
  void EncryptBlock(uint64_t* in, uint64_t* out);
  void Encrypt(int size, byte* in, byte* out);
  void DecryptBlock(uint64_t* in, uint64_t* out);
  void Decrypt(int size, byte* in, byte* out);
  bool GetCtr(byte* out);
};

class AesGcm : public EncryptionAlgorithm {

private:
  int direction_;
  bool output_verified_;
  int size_tag_;
  uint64_t encrypted_iv_[2];

  GAesCtr aesctr_;
  Ghash ghash_;

 public:
  enum {ENCRYPT = 0, DECRYPT = 1};
  AesGcm();
  ~AesGcm();

  bool Init(int size_key, byte* key, int size_tag,
            int size_iv, byte* iv,
            int direction, bool use_aesni);
  void PrintEncryptionAlgorithm();
  bool ProcessInput(int size_in, byte* in, int* size_out,
                    byte* out) {return false;}
  bool ProcessFinalInput(int size_in, byte* in, int* size_out,
                         byte* out) {return false;}
  int InputBytesProcessed() {return 0;}
  int OutputBytesProduced() {return 0;}

  int GetComputedTag(int size, byte* out);
  int SetReceivedTag(int size, byte* in);

  bool AuthenticatedIn(int size_in, byte* in);
  bool FinalAuthenticatedIn(int size_in, byte* in);

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

  bool MessageValid();
  bool GenerateScheme(const char* name, int num_bits);
  bool MakeScheme(const char* name, int num_key_bits,
                  byte* key, byte* iv);
};

#endif
