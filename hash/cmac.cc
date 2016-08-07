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
// File: cmac.cc

#include "cryptotypes.h"
#include "util.h"
#include "hash.h"
#include "cmac.h"
#include "aes.h"
#include <string>
#include <string.h>
using namespace std;

// This implementation assumes a little-endian platform.

/*
 *  CMAC(M1,...,Mm)
 *    if M_n* is complete M_n = M_n* ^ K1 else M_n = M_n*||0 ^ K2
 *    for (i=1, i<n i++) C_i = E_K(C_(i-1) ^ M_i);
 *    T = msb_(tlen)(Cn)
 *    return T
 */

/*
 *  CMAC: test vectors
 *
 *  K: 2b7e1516 28aed2a6 abf71588 09cf4f3c.
 *  Subkey Generation
 *  CIPHK(0^128): 7df76b0c 1ab899b3 3e42f047 b91b546f
 *  K1: fbeed618 35713366 7c85e08f 7236a8de
 *  K2: f7ddac30 6ae266cc f90bc11e e46d513b
 *  Example 2: Mlen = 128
 *  M:  6bc1bee2 2e409f96 e93d7e11 7393172a
 *  T:  070a16b4 6b4d4144 f79bdd9d d04a287c
 *  Example 3: Mlen = 320
 *  M:  6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51
 *  30c81c46 a35ce411
 *  T:  dfa66747 de9ae630 30ca3261 1497c827
 *  Example 4: Mlen = 512
 *  M:  6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51
 *  30c81c46 a35ce411 e5fbc119 1a0a52ef f69f2445 df4f9b17 ad2b417b e66c3710
 *  T:  51f0bebf 7e3b9d92 fc497417 79363cfe 
 */

Cmac::Cmac(int num_bits) { num_out_bytes_ = (num_bits + NBITSINBYTE - 1) / NBITSINBYTE; }

Cmac::~Cmac() {}

bool Cmac::ComputeSubKeys(byte* K) {
  byte in[Aes::BLOCKBYTESIZE];
  byte L[Aes::BLOCKBYTESIZE];

  memset(in, 0, Aes::BLOCKBYTESIZE);
  memset(L, 0, Aes::BLOCKBYTESIZE);
  if (!aes_.Init(128, K, Aes::ENCRYPT)) return false;
  aes_.EncryptBlock(in, L);

  // if (msb(L) == 0) K_1 = L <<1; else K_1 = L<<1 ^ R
  for (int i = 0; i< 15; i++)
    K1_[i] = (L[i] << 1) | L[i + 1] >> 7;
  K1_[15] = (L[15] << 1);
  if ((L[0]&0x80) !=0) {
    for (int i = 0; i< 16; i++)
      K1_[i] ^= R_[i];
  }

  // if (msb(K1) ==0) K2 = K1 << 1 else K2 = (K1<<1) ^ R
  for (int i = 0; i< 15; i++)
    K2_[i] = (K1_[i] << 1) | K1_[i + 1] >> 7;
  K2_[15] = (K1_[15] << 1);
  if ((K1_[0]&0x80) !=0) {
    for (int i = 0; i< 16; i++)
      K2_[i] ^= R_[i];
  }
  return true;
}

bool Cmac::Init(byte* K) {
  if (num_out_bytes_ > BLOCKBYTESIZE) return false;
  if (!ComputeSubKeys(K)) return false;

  printf("K :"); PrintBytes(16, K); printf("\n");
  printf("K1:"); PrintBytes(16, K1_); printf("\n");
  printf("K2:"); PrintBytes(16, K2_); printf("\n");

  memset((byte*)state_, 0, sizeof(state_));
  num_bytes_waiting_ = 0;
  num_bits_processed_ = 0;
  finalized_ = false;
  return true;
}

void Cmac::AddToHash(int size, const byte* in) {
  /*
  if (num_bytes_waiting_ > 0) {
    int needed = BLOCKBYTESIZE - num_bytes_waiting_;
    if (size < needed) {
      memcpy(&bytes_waiting_[num_bytes_waiting_], in, size);
      num_bytes_waiting_ += size;
      return;
    }
    memcpy(&bytes_waiting_[num_bytes_waiting_], in, needed);
    TransformBlock((const uint64_t*)bytes_waiting_,
                   BLOCKBYTESIZE / sizeof(uint64_t));
    num_bits_processed_ += BLOCKBYTESIZE * NBITSINBYTE;
    size -= needed;
    in += needed;
    num_bytes_waiting_ = 0;
  }
  while (size >= BLOCKBYTESIZE) {
    TransformBlock((const uint64_t*)in, BLOCKBYTESIZE / sizeof(uint64_t));
    num_bits_processed_ += BLOCKBYTESIZE * NBITSINBYTE;
    size -= BLOCKBYTESIZE;
    in += BLOCKBYTESIZE;
  }
  if (size > 0) {
    num_bytes_waiting_ = size;
    memcpy(bytes_waiting_, in, size);
  }
 */
}

bool Cmac::GetDigest(int size, byte* out) {
  if (!finalized_) return false;
  if (size < num_out_bytes_) return false;
  memcpy(out, digest_, num_out_bytes_);
  return true;
}

void Cmac::Final() {
  /*
  bytes_waiting_[num_bytes_waiting_++] = 0x1;
  memset(&bytes_waiting_[num_bytes_waiting_], 0,
         BLOCKBYTESIZE - num_bytes_waiting_);
  bytes_waiting_[BLOCKBYTESIZE - 1] |= 0x80;
  TransformBlock((const uint64_t*)bytes_waiting_,
                 BLOCKBYTESIZE / sizeof(uint64_t));
  memset(digest_, 0, 128);
  memcpy(digest_, state_, num_out_bytes_);
  */
  finalized_ = true;
}
