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
// File: crypto_scheme.h

#include "cryptotypes.h"
#include "util.h"
#include "symmetric_cipher.h"
#include "keys.pb.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#ifndef _CRYPTO_ENCRYPTION_ALGORITHM_H__
#define _CRYPTO_ENCRYPTION_ALGORITHM_H__
using namespace std;


class EncryptionAlgorithm {
public:
  enum {
    ENCRYPT= 1,
    DECRYPT= 2
  };
  string*   alg_name_;
  string*   message_id_;
  bool      initialized_;
  int       direction_;
  int       input_bytes_processed_;
  int       output_bytes_produced_;

  EncryptionAlgorithm();
  virtual ~EncryptionAlgorithm();

  bool     ReadEncryptionAlgorithm(string& filename);
  bool     SaveEncryptionAlgorithm(string& filename);
  bool     SerializeEncryptionAlgorithmToMessage(crypto_encryption_algorithm_message&);
  bool     DeserializeEncryptionAlgorithmFromMessage(crypto_encryption_algorithm_message&);

  virtual int   DecryptInputQuantum()= 0;
  virtual int   EncryptInputQuantum()= 0;
  virtual int   MinimumFinalDecryptIn()= 0;
  virtual int   MinimumFinalEncryptIn()= 0;
  virtual int   MaxAdditionalOutput()= 0;
  virtual int   MaxAdditionalFinalOutput()= 0;
  virtual bool  ProcessInput(int size_in, byte* in, int* size_out, byte* out)= 0;
  virtual bool  ProcessFinalInput(int size_in, byte* in, int* size_out, byte* out)= 0;
  virtual int   InputBytesProcessed()= 0;
  virtual int   OutputBytesProduced()= 0;
  virtual bool  MessageValid()= 0;
};

//
//  Subclasses to implement
//
//    aes128-cbc-hmacsha256-sympad
//    aes-ecb-sympad
//    aes-ctr-hmacsha256-sympad
//    aes-gcm-sympad
#endif

