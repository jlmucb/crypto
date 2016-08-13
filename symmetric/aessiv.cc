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

bool AesSiv::ComputeSubKeys(byte* K) {
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

#define DEBUG
bool AesSiv::Encrypt(byte* K, int hdr_size, byte* hdr, int msg_size, byte* msg, int* size_out, byte*out) {
  Cmac cmac(128);

  if (!ComputeSubKeys(K)) {
    LOG(ERROR) << "AesSiv::Encrypt: ComputeSubKeys fails\n";
    return false;
  }
#ifdef DEBUG
    printf("Siv-Encrypt, K1_: "); PrintBytes(Aes::BLOCKBYTESIZE, K1_); printf("\n");
    printf("Siv-Encrypt, K2_: "); PrintBytes(Aes::BLOCKBYTESIZE, K2_); printf("\n");
    printf("\n");
#endif
  if (!cmac.Init(K1_)) {
    LOG(ERROR) << "AesSiv::Encrypt: cmac.Init fails\n";
    return false;
  }
  int all_size = hdr_size + msg_size;
  byte* all = (byte*)malloc(all_size);
  if (all == nullptr) {
    LOG(ERROR) << "AesSiv::Encrypt: malloc fails\n";
    return false;
  }
  memcpy(all, hdr, hdr_size);
  memcpy(&all[hdr_size], msg, msg_size);
  int first_size = (all_size/Aes::BLOCKBYTESIZE) * Aes::BLOCKBYTESIZE;
  int last_size;
  if (first_size == hdr_size) {
    last_size = Aes::BLOCKBYTESIZE;
    first_size -= Aes::BLOCKBYTESIZE;
  } else {
    last_size = all_size - Aes::BLOCKBYTESIZE;
  }
  cmac.AddToHash(first_size, all);
  cmac.Final(last_size, &all[first_size]);
  free(all);
  all = nullptr;
  if (!cmac.GetDigest(Aes::BLOCKBYTESIZE, iv_)) {
    LOG(ERROR) << "AesSiv::Encrypt: GetDigest fails\n";
    return false;
  }
#ifdef DEBUG
    printf("Siv-Encrypt, after GetDigest: "); PrintBytes(Aes::BLOCKBYTESIZE, iv_); printf("\n");
    printf("\n");
#endif

  // Now encrypt with counter mode with key, K2 and ctr initialized to IV & 1^(n−64) 01^31 01^31
  if (!aes_.Init(128, K2_, Aes::ENCRYPT)) {
    LOG(ERROR) << "AesSiv::Encrypt: Aes::Init fails\n";
    return false;
  }
  memcpy(ctr_blk_, iv_, Aes::BLOCKBYTESIZE);

  byte* outptr = out;
  byte* inptr = msg;

  // out = iv_ || C
  memcpy(outptr, iv_, Aes::BLOCKBYTESIZE);
  outptr += Aes::BLOCKBYTESIZE;
  int num_blocks = (msg_size + Aes::BLOCKBYTESIZE - 1) / Aes::BLOCKBYTESIZE;
  byte to_xor[Aes::BLOCKBYTESIZE];

#ifdef DEBUG
    printf("Siv-Encrypt, num_blocks: %d\n", num_blocks);
    printf("\n");
#endif

  for (int i = 0; i < num_blocks; i++) {
    aes_.EncryptBlock(ctr_blk_, to_xor);
    Xor(inptr, to_xor, outptr, Aes::BLOCKBYTESIZE);
#ifdef DEBUG
    printf("Encrypt, ctr: "); PrintBytes(Aes::BLOCKBYTESIZE, ctr_blk_); printf("\n");
    printf("Encrypt, in : "); PrintBytes(Aes::BLOCKBYTESIZE, inptr); printf("\n");
    printf("Encrypt, out: "); PrintBytes(Aes::BLOCKBYTESIZE, outptr); printf("\n");
    printf("\n");
#endif
    BumpCtr(ctr_blk_);
    outptr += Aes::BLOCKBYTESIZE;
    inptr += Aes::BLOCKBYTESIZE;
  }

  *size_out = num_blocks * Aes::BLOCKBYTESIZE + Aes::BLOCKBYTESIZE;
  return true;
}

bool AesSiv::Decrypt(byte* K, int hdr_size, byte* hdr, int cipher_size, byte* cipher, int* size_out, byte* out) {
  Cmac cmac(128);

  if (!ComputeSubKeys(K)) {
    LOG(ERROR) << "AesSiv::Encrypt: ComputeSubKeys fails\n";
    return false;
  }
#ifdef DEBUG
    printf("Siv-Decrypt, K1_: "); PrintBytes(Aes::BLOCKBYTESIZE, K1_); printf("\n");
    printf("Siv-Decrypt, K2_: "); PrintBytes(Aes::BLOCKBYTESIZE, K2_); printf("\n");
    printf("\n");
#endif

  // Now decrypt with counter mode with key, K2 and ctr initialized to IV & 1^(n−64) 01^31 01^31
  if (!aes_.Init(128, K2_, Aes::ENCRYPT)) {
    LOG(ERROR) << "AesSiv::Decrypt: Aes::Init fails\n";
    return false;
  }

  byte* outptr = out;
  byte* inptr = cipher;
  memcpy(iv_, inptr, Aes::BLOCKBYTESIZE);
  inptr += Aes::BLOCKBYTESIZE;
  memcpy(ctr_blk_, iv_, Aes::BLOCKBYTESIZE);

  int num_blocks = (cipher_size - 1) / Aes::BLOCKBYTESIZE;
  byte to_xor[Aes::BLOCKBYTESIZE];

#ifdef DEBUG
    printf("Siv-Decrypt, num_blocks: %d\n", num_blocks);
    printf("\n");
#endif

  for (int i = 0; i < num_blocks; i++) {
    aes_.EncryptBlock(ctr_blk_, to_xor);
    Xor(inptr, to_xor, outptr, Aes::BLOCKBYTESIZE);
#ifdef DEBUG
    printf("Decrypt, ctr: "); PrintBytes(Aes::BLOCKBYTESIZE, ctr_blk_); printf("\n");
    printf("Decrypt, in : "); PrintBytes(Aes::BLOCKBYTESIZE, inptr); printf("\n");
    printf("Decrypt, out: "); PrintBytes(Aes::BLOCKBYTESIZE, outptr); printf("\n");
    printf("\n");
#endif
    BumpCtr(ctr_blk_);
    outptr += Aes::BLOCKBYTESIZE;
    inptr += Aes::BLOCKBYTESIZE;
  }
  *size_out = num_blocks * Aes::BLOCKBYTESIZE;

  if (!cmac.Init(K1_)) {
    LOG(ERROR) << "AesSiv::Decrypt: cmac.Init fails\n";
    return false;
  }
  int all_size = hdr_size + *size_out;
  byte* all = (byte*)malloc(all_size);
  if (all == nullptr) {
    LOG(ERROR) << "AesSiv::Decrypt: malloc fails\n";
    return false;
  }
  memcpy(all, hdr, hdr_size);
  memcpy(&all[hdr_size], out, *size_out);
  int first_size = (all_size/Aes::BLOCKBYTESIZE) * Aes::BLOCKBYTESIZE;
  int last_size;
  if (first_size == hdr_size) {
    last_size = Aes::BLOCKBYTESIZE;
    first_size -= Aes::BLOCKBYTESIZE;
  } else {
    last_size = all_size - Aes::BLOCKBYTESIZE;
  }
  cmac.AddToHash(first_size, all);
  cmac.Final(last_size, &all[first_size]);
  free(all);
  all = nullptr;
  byte computed_iv[16];
  if (!cmac.GetDigest(Aes::BLOCKBYTESIZE, computed_iv)) {
    LOG(ERROR) << "AesSiv::Decrypt: GetDigest fails\n";
    return false;
  }
#ifdef DEBUG
    printf("Siv-Decrypt, after GetDigest: "); PrintBytes(Aes::BLOCKBYTESIZE, computed_iv); printf("\n");
    printf("\n");
#endif

  return true;
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
