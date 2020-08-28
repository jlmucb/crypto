// Copyright 2020 John Manferdelli, All Rights Reserved.
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
// File: crypto_names.cc

#include "crypto_support.h"
#include "crypto_names.h"

const char* g_schemes[num_schemes] = {
    "aes128-ctr-hmacsha256-sympad",
    "aes128-cbc-hmacsha256-sympad",
    "aes128-ecb-hmacsha256-sympad",
    "aes256-ctr-hmacsha512-sympad",
    "aes256-cbc-hmacsha512-sympad",
    "aes256-ecb-hmacsha512-sympad",
};

const char* g_algorithms[num_algorithms] = {
  "rsa ", "ecc", "aes", "rc4",
  "tea", "twofish", "simon", "spec",
  "sha1", "sha2", "sha3", "shaHmac",
};

const char* g_operations[num_operations] = {
  "toBase64",
  "fromBase64",
  "toHex",
  "fromHex",
  "getRandom",
  "deriveKey",
  "generateKey ",
  //type size parameters name purpose output
  "readKey",
  "generateEncryptionSchemeParameters",
  "readEncryptionSchemeParameters",
  "decryptScheme",
  "encryptScheme",
  "computeHash",
  "computeMac",
  "verifyHmac",
  "encryptWithPassword",
  "decryptWithPassword",
};

void print_schemes() {
  for (int i = 0; i < num_schemes; i++)
    printf("  %s\n", g_schemes[i]);
}

void print_algorithms() {
  for (int i = 0; i < num_algorithms; i++)
    printf("  %s\n", g_algorithms[i]);
}

void print_operations() {
  for (int i = 0; i < num_operations; i++)
    printf("  %s\n", g_operations[i]);
}

