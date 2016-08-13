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

#define DEBUG

// This implementation assumes a little-endian platform.

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

#ifdef DEBUG
  printf("K : "); PrintBytes(16, K); printf("\n");
  printf("K1: "); PrintBytes(16, K1_); printf("\n");
  printf("K2: "); PrintBytes(16, K2_); printf("\n");
#endif

  memset((byte*)state_, 0, sizeof(state_));
  num_bytes_waiting_ = 0;
  num_bits_processed_ = 0;
  finalized_ = false;
  return true;
}

void Cmac::AddToHash(int size, const byte* in) {
  byte t[BLOCKBYTESIZE];

  if (num_bytes_waiting_ > 0) {
    int needed = BLOCKBYTESIZE - num_bytes_waiting_;
    if (size < needed) {
      memcpy(&bytes_waiting_[num_bytes_waiting_], in, size);
      num_bytes_waiting_ += size;
      return;
    }
    memcpy(&bytes_waiting_[num_bytes_waiting_], in, needed);
    // add to hash
    for (int i = 0; i < BLOCKBYTESIZE; i++)
      t[i] = state_[i] ^ bytes_waiting_[i];
    aes_.EncryptBlock(t, state_);
    num_bits_processed_ += BLOCKBYTESIZE * NBITSINBYTE;
    size -= needed;
    in += needed;
    num_bytes_waiting_ = 0;
  }
  while (size >= BLOCKBYTESIZE) {
      for (int i = 0; i < BLOCKBYTESIZE; i++)
        t[i] = state_[i] ^ in[i];
      aes_.EncryptBlock(t, state_);
    num_bits_processed_ += BLOCKBYTESIZE * NBITSINBYTE;
    size -= BLOCKBYTESIZE;
    in += BLOCKBYTESIZE;
  }
  if (size > 0) {
    num_bytes_waiting_ = size;
    memcpy(bytes_waiting_, in, size);
  }
}

void Cmac::Final(int size, byte* in) {
  byte blk[BLOCKBYTESIZE];

  memset(blk, 0, BLOCKBYTESIZE);
  if (size == BLOCKBYTESIZE) {
    for (int i = 0; i < BLOCKBYTESIZE; i++)
      blk[i] = in[i] ^ K1_[i];
  } else {
    for (int i = 0; i < size; i++)
      blk[i] = in[i] ^ K2_[i];
    for (int i = size; i < BLOCKBYTESIZE; i++)
      blk[i] = K2_[i];
  }
  aes_.EncryptBlock(blk, digest_);
  finalized_ = true;
}

bool Cmac::GetDigest(int size, byte* out) {
  if (!finalized_) return false;
  if (size < num_out_bytes_) return false;
  memcpy(out, digest_, num_out_bytes_);
  return true;
}
