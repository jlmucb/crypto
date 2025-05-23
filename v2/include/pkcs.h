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
// File: pkcs.h

#include "crypto_support.h"
#include "hash.h"
#include "sha256.h"

#ifndef _CRYPTO_PKCS_H__
#define _CRYPTO_PKCS_H__
const int pkcs_sha256_sigblock_size = 58;

bool pkcs_encode(const char* hash_alg, byte_t* hash, int out_size, byte_t* out);
bool pkcs_verify(const char* hash_alg, byte_t* hash, int in_size, byte_t* in);
bool pkcs_embed(int in_size, byte_t* in, int out_size, byte_t* out);
bool pkcs_extract(int in_size, byte_t* in, int* out_size, byte_t* out);
#endif
