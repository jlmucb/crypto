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
// File: pbkdf.h

#include "cryptotypes.h"
#include "hash.h"
#include "sha256.h"
#include <string>
#include <stdio.h>

#ifndef _CRYPTO_PBKDF_H__
#define _CRYPTO_PBKDF_H__
using namespace std;

bool pbkdf2(const char* pass, int saltLen, byte* salt, int iter, 
            int out_size, byte* out);
#endif

