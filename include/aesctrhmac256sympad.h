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
// File: aesctrhmac256sympad.h

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
#include "hmac_sha256.h"

#ifndef _CRYPTO_AESCTRHMAC256SYMPAD_H__
#define _CRYPTO_AESCTRHMAC256SYMPAD_H__

using std::string;

class AesCtrHmac256Sympad : public EncryptionAlgorithm {
 public:
  bool use_aesni_;

  Aes aes_obj_;
  AesNi aesni_obj_;
  HmacSha256 hmac_;
  byte iv_[32];
  byte ctr_blk_[Aes::BLOCKBYTESIZE];

  int num_unprocessed_input_bytes_;
  byte input_buf[Aes::BLOCKBYTESIZE];

  unsigned* ctr_;

  bool iv_processed_;
  byte hmac_received_[HmacSha256::MACBYTESIZE];
  byte hmac_computed_[HmacSha256::MACBYTESIZE];

  bool output_verified_;

  AesCtrHmac256Sympad();
  ~AesCtrHmac256Sympad();

  void PrintEncryptionAlgorithm();

  void CtrEncryptBlock(byte* in, byte* out, int);
  void CtrDecryptBlock(byte* in, byte* out, int);

  bool PlainIn(int size_in, byte* in, int* size_out, byte* out);
  bool CipherIn(int size_in, byte* in, int* size_out, byte* out);
  bool FinalPlainIn(int size_in, byte* in, int* size_out, byte* out);
  bool FinalCipherIn(int size_in, byte* in, int* size_out, byte* out);

  bool Init(int size_enc, byte* enc_key, int size_int, byte* int_key,
            int size_nonce, byte* nonce, int size_iv, byte* iv, bool use_aesni);

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

  int GetComputedMac(int size, byte*);
  int GetReceivedMac(int size, byte*);

  bool GenerateScheme(const char* name, int num_bits);
  bool MakeScheme(const char* name, int num_bits, byte* enc_key, byte* int_key,
                  byte* nonce, byte* iv);
};

#endif
