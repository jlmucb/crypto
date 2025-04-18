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
// File: pbkdf2.cc

#include "crypto_support.h"
#include "hash.h"
#include "sha256.h"
#include "hmac_sha256.h"


//  pbkdf2
//  Input: P Password, S Salt, C Iteration count
//   kLen Length of MK in bits; at most (2^32-1)xhLen
//  Parameter: PRF HMAC with an approved hash function
//    hlen Digest size of the hash function
//  Output: mk Master key
//  Algorithm:
//    len = ceil(kLen/hLen);
//    r = kLen–(len–1)xhLen ;
//   for i = 1 to len {
//      T[i]= 0;
//      U[0]= S || Int(i);
//      for j = 1 to C {
//        U[j]= HMAC(P, U[j-1])
//        T[i]= T[i]^U[j]
//      }
//    }
//  return MK = T[1] || T[2] || ...
bool pbkdf2(const char* pass, int saltLen, byte_t* salt, int iter, int out_size,
            byte_t* out) {
  hmac_sha256 hmac;
  int k = strlen(pass);
  int i, j, m;
  int n = (out_size + hmac_sha256::MACBYTESIZE - 1) / hmac_sha256::MACBYTESIZE;
  byte_t t[hmac_sha256::BLOCKBYTESIZE];
  byte_t u[hmac_sha256::MACBYTESIZE];
  int left = out_size;
  byte_t t_out[hmac_sha256::MACBYTESIZE];
  byte_t* next_out = out;

  memset(t, 0, hmac_sha256::BLOCKBYTESIZE);
  memset(u, 0, hmac_sha256::MACBYTESIZE);
  if (saltLen > (int)(hmac_sha256::MACBYTESIZE - sizeof(int)))
    saltLen = hmac_sha256::MACBYTESIZE - sizeof(int);
  memcpy(u, salt, saltLen);
  for (i = 0; i < n; i++) {
    memcpy(&u[saltLen], (byte_t*)&i, sizeof(int));
    memset(t, 0, hmac_sha256::BLOCKBYTESIZE);
    for (j = 0; j < iter; j++) {
      hmac.init(k, (byte_t*)pass);
      hmac.add_to_inner_hash(hmac_sha256::MACBYTESIZE, u);
      hmac.finalize();
      hmac.get_hmac(hmac_sha256::MACBYTESIZE, t_out);
      for (m = 0; m < hmac_sha256::MACBYTESIZE; m++) t[m] ^= t_out[m];
      memcpy(t, t_out, hmac_sha256::MACBYTESIZE);
      if (left < hmac_sha256::MACBYTESIZE) {
        memcpy(next_out, t, left);
        left = 0;
      } else {
        memcpy(next_out, t, hmac_sha256::MACBYTESIZE);
        left -= hmac_sha256::MACBYTESIZE;
        next_out += hmac_sha256::MACBYTESIZE;
      }
    }
  }
  return true;
}
