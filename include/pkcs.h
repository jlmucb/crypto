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
// File: pkcs.h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <memory>

#include "cryptotypes.h"
#include "hash.h"
#include "sha256.h"

#ifndef _CRYPTO_PKCS_H__
#define _CRYPTO_PKCS_H__

bool PkcsEncode(const char* hash_alg, byte* hash, int out_size, byte* out);
bool PkcsVerify(const char* hash_alg, byte* hash, int in_size, byte* in);
bool PkcsEmbed(int in_size, byte* in, int out_size, byte* out);
bool PkcsExtract(int in_size, byte* in, int* out_size, byte* out);
#endif
