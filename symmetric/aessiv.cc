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
// File: aessiv.cc

#include "cryptotypes.h"
#include "util.h"
#include "conversions.h"
#include "symmetric_cipher.h"
#include "encryption_algorithm.h"
#include "aes.h"
#include "sha256.h"
#include "aessiv.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>

AesSiv::AesSiv() {
  num_unprocessed_input_bytes_ = 0;
  memset(ctr_blk_, 0, Aes::BLOCKBYTESIZE);
  memset(K1_, 0, Aes::BLOCKBYTESIZE);
  memset(K2_, 0, Aes::BLOCKBYTESIZE);
  initialized_ = false;
}

AesSiv::~AesSiv() {
  initialized_ = false;
}

static void BumpCtr(byte* ctr) {
  uint64_t* add = (uint64_t*) ctr;
  *add += 1ULL;
  if (*add != 0ULL)
    return;
  add++;
  *add += 1ULL;
  if (*add != 0ULL)
    return;
  add++;
  *add += 1ULL;
  if (*add != 0ULL)
    return;
  add++;
  *add += 1ULL;
    return;
}

static void Xor(byte* in, byte* to_xor, byte* out, int size) {
  for (int i = 0; i < size; i++)
    out[i] = in[i] ^ to_xor[i];
}

static void setCtr(byte* in, byte* out) {
  // ctr initialized to IV & 1^(n−64) 01^31 01^31
  byte pad[4] = {0x7f, 0xff, 0xff, 0xff};
  memcpy(out, in, 8);
  Xor(&in[8], pad, &out[8], 4);
  Xor(&in[12], pad, &out[12], 4);
}

static void dbl(byte* in, byte* out) {
  bool msb = ((in[0]&0x80) != 0);

  for (int i = 0; i < (Aes::BLOCKBYTESIZE - 1); i++) {
    out[i] = (in[i] << 1) | (in[i + 1] >> 7);
  }
  out[Aes::BLOCKBYTESIZE - 1] = in[Aes::BLOCKBYTESIZE - 1] << 1;
  if (msb) {
    out[Aes::BLOCKBYTESIZE - 1] ^= 0x87;
  }
}

/*
 * CMAC∗ (X1,...,Xm)
 *   S ← CMAC_K(0^n)
 *   for i=1 i<= m−1  S=dbl(S)⊕CMACK(Xi)
 *   if |Xm| ≥ n then return CMACK (S ⊕end Xm)
 *   else return CMACK (dbl(S) ⊕ Xm10∗)
 */
#define DEBUG

static bool CalcIv(byte* K, int size, byte* in, byte* out) {

  byte zero[Aes::BLOCKBYTESIZE];
  byte S[Aes::BLOCKBYTESIZE];
  byte X[Aes::BLOCKBYTESIZE];
  byte Y[Aes::BLOCKBYTESIZE];
  byte T[Aes::BLOCKBYTESIZE];

  memset(zero, 0, Aes::BLOCKBYTESIZE);
  memset(out, 0, Aes::BLOCKBYTESIZE);

  Cmac cmac(128);
  cmac.Init(K);
  cmac.Final(Aes::BLOCKBYTESIZE, zero);
  cmac.GetDigest(Aes::BLOCKBYTESIZE, S); 

#ifdef DEBUG
  printf("\n");
  printf("K        : "); PrintBytes(16, K); printf("\n");
  printf("in       : "); PrintBytes(16, in); printf("\n");
  printf("First S  : "); PrintBytes(16, S); printf("\n");
  printf("Should be: 0e04dfafc1efbf040140582859bf073a\n");
  printf("\n");
#endif

  int num_blocks = size / Aes::BLOCKBYTESIZE;
  if ((Aes::BLOCKBYTESIZE * num_blocks) == size)
    num_blocks--;
  int last_size = size - num_blocks * Aes::BLOCKBYTESIZE;
  byte* inptr = in;
  for (int i = 0; i < num_blocks; i++) {
    cmac.Init(K);
    cmac.AddToHash(0, zero);
    cmac.Final(16, inptr);
    cmac.GetDigest(16, T); 
    dbl(S, X);
    Xor(X, T, S, Aes::BLOCKBYTESIZE);
    inptr += Aes::BLOCKBYTESIZE;
  }
  memset(Y, 0, Aes::BLOCKBYTESIZE);
  memcpy(Y, inptr, last_size);
  if (last_size < Aes::BLOCKBYTESIZE) {
    Y[last_size] = 0x80;
  }
  dbl(S, X);
  Xor(Y, X, T, Aes::BLOCKBYTESIZE);
  cmac.Init(K);
  cmac.AddToHash(0, zero);
  cmac.Final(16, T);
  cmac.GetDigest(16, out); 
  return true;
}

bool AesSiv::Encrypt(byte* K, int hdr_size, byte* hdr, int msg_size, byte* msg, int* size_out, byte*out) {

  memcpy(K1_, &K[0], Aes::BLOCKBYTESIZE);
  memcpy(K2_, &K[16], Aes::BLOCKBYTESIZE);

#ifdef DEBUG
    printf("\n");
    printf("Siv-Encrypt, K1_: "); PrintBytes(Aes::BLOCKBYTESIZE, K1_); printf("\n");
    printf("Siv-Encrypt, K2_: "); PrintBytes(Aes::BLOCKBYTESIZE, K2_); printf("\n");
    printf("\n");
#endif

  *size_out = msg_size + Aes::BLOCKBYTESIZE;

  int all_size = hdr_size + msg_size;
  byte* all = (byte*)malloc(all_size);
  if (all == nullptr) {
    LOG(ERROR) << "AesSiv::Encrypt: malloc fails\n";
    return false;
  }
  memcpy(all, hdr, hdr_size);
  memcpy(&all[hdr_size], msg, msg_size);

  if (!CalcIv(K1_, all_size, all, iv_)) {
    LOG(ERROR) << "AesSiv::Encrypt: CalcIv fails\n";
    return false;
  }

#ifdef DEBUG
    printf("\n");
    printf("Siv-Encrypt, to digest: "); PrintBytes(all_size, all); printf("\n");
    printf("Siv-Encrypt, iv: "); PrintBytes(Aes::BLOCKBYTESIZE, iv_); printf("\n");
    printf("\n");
#endif

  free(all);
  all = nullptr;

  if (!aes_.Init(128, K2_, Aes::ENCRYPT)) {
    LOG(ERROR) << "AesSiv::Encrypt: Aes::Init fails\n";
    return false;
  }

  setCtr(iv_, ctr_blk_);

  byte* outptr = out;
  byte* inptr = msg;

  // out = iv_ || C
  memcpy(outptr, iv_, Aes::BLOCKBYTESIZE);
  outptr += Aes::BLOCKBYTESIZE;
  byte to_xor[Aes::BLOCKBYTESIZE];

  int bytes_to_process = msg_size;
  int bytes_processed;

  while (bytes_to_process > 0) {
    aes_.EncryptBlock(ctr_blk_, to_xor);
    if (bytes_to_process >= Aes::BLOCKBYTESIZE) {
        bytes_processed = Aes::BLOCKBYTESIZE;
    } else {
        bytes_processed = bytes_to_process;
    }
    Xor(inptr, to_xor, outptr, bytes_processed);
    bytes_to_process -= bytes_processed;
    outptr += bytes_processed;
    inptr += bytes_processed;
    BumpCtr(ctr_blk_);
  }

  return true;
}

bool AesSiv::Decrypt(byte* K, int hdr_size, byte* hdr, int cipher_size, byte* cipher, int* size_out, byte* out) {

  memcpy(K1_, &K[0], Aes::BLOCKBYTESIZE);
  memcpy(K2_, &K[16], Aes::BLOCKBYTESIZE);

#ifdef DEBUG
    printf("\n");
    printf("Siv-Decrypt, K1_: "); PrintBytes(Aes::BLOCKBYTESIZE, K1_); printf("\n");
    printf("Siv-Decrypt, K2_: "); PrintBytes(Aes::BLOCKBYTESIZE, K2_); printf("\n");
    printf("\n");
#endif

  *size_out = cipher_size - Aes::BLOCKBYTESIZE;

  // Now decrypt with counter mode with key, K2 and ctr initialized to IV & 1^(n−64) 01^31 01^31
  if (!aes_.Init(128, K2_, Aes::ENCRYPT)) {
    LOG(ERROR) << "AesSiv::Decrypt: Aes::Init fails\n";
    return false;
  }

  byte* outptr = out;
  byte* inptr = cipher;

  memcpy(iv_, inptr, Aes::BLOCKBYTESIZE);
  inptr += Aes::BLOCKBYTESIZE;

  setCtr(iv_, ctr_blk_);

  int bytes_to_process = *size_out;
  byte to_xor[Aes::BLOCKBYTESIZE];
  int bytes_processed;

  while (bytes_to_process > 0) {
    aes_.EncryptBlock(ctr_blk_, to_xor);
    if (bytes_to_process >= Aes::BLOCKBYTESIZE) {
        bytes_processed = Aes::BLOCKBYTESIZE;
    } else {
        bytes_processed = bytes_to_process;
    }
    bytes_to_process -= bytes_processed;
    Xor(inptr, to_xor, outptr, bytes_processed);
    outptr += bytes_processed;
    inptr += bytes_processed;
    BumpCtr(ctr_blk_);
  }

  int all_size = hdr_size + *size_out;
  byte* all = (byte*)malloc(all_size);
  if (all == nullptr) {
    LOG(ERROR) << "AesSiv::Decrypt: malloc fails\n";
    return false;
  }
  memcpy(all, hdr, hdr_size);
  memcpy(&all[hdr_size], out, *size_out);

  byte computed_iv[16];

  if (!CalcIv(K1_, all_size, all, computed_iv)) {
    LOG(ERROR) << "AesSiv::Encrypt: CalcIv fails\n";
    return false;
  }

#ifdef DEBUG
    printf("\n");
    printf("Siv-Decrypt, to digest: "); PrintBytes(all_size, all); printf("\n");
    printf("Siv-Decrypt, calculated iv: "); PrintBytes(Aes::BLOCKBYTESIZE, computed_iv); printf("\n");
    printf("\n");
#endif

  free(all);
  all = nullptr;

  return memcmp(computed_iv, iv_, Aes::BLOCKBYTESIZE) == 0;
}

bool AesSiv::GenerateScheme(const char* name, int num_bits) {
  return true;
}

bool AesSiv::MakeScheme(const char* id, int num_bits, byte* enc_key,
                        byte* int_key, byte* nonce, byte* iv) {
  /*
  return Init(num_bits / NBITSINBYTE, enc_key, num_bits / NBITSINBYTE, int_key,
              4, nonce, 8, iv, false);
   */
  return true;
}
