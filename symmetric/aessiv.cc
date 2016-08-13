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

/*
 * IV = CMAC∗ (X1,...,Xm)
 * dbl(S) is S<<1 if msb(S) = 0 and dbl(S) = (S<<1) ^ 0**(120)10000111 if msb(S) = 1.
 * CMAC∗ (X1,...,Xm)
 *   S ← CMAC_K(0^n)
 *   for i=1 i<= m−1  S=dbl(S)⊕CMACK(Xi)
 *   if |Xm| ≥ n then return CMACK (S ⊕end Xm)
 *   else return CMACK (dbl(S) ⊕ Xm10∗)
 */

#define DEBUG
bool AesSiv::Encrypt(byte* K, int hdr_size, byte* hdr, int msg_size, byte* msg, int* size_out, byte*out) {
  Cmac cmac(128);

  memcpy(K1_, &K[0], Aes::BLOCKBYTESIZE);
  memcpy(K2_, &K[16], Aes::BLOCKBYTESIZE);

#ifdef DEBUG
    printf("\n");
    printf("Siv-Encrypt, K1_: "); PrintBytes(Aes::BLOCKBYTESIZE, K1_); printf("\n");
    printf("Siv-Encrypt, K2_: "); PrintBytes(Aes::BLOCKBYTESIZE, K2_); printf("\n");
    printf("\n");
#endif

  *size_out = msg_size + Aes::BLOCKBYTESIZE;

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
    first_size -= Aes::BLOCKBYTESIZE;
  }
  last_size = all_size - first_size;

  cmac.AddToHash(first_size, all);
  cmac.Final(last_size, &all[first_size]);
  if (!cmac.GetDigest(Aes::BLOCKBYTESIZE, iv_)) {
    LOG(ERROR) << "AesSiv::Encrypt: GetDigest fails\n";
    return false;
  }

#ifdef DEBUG
    printf("\n");
    printf("Siv-Encrypt, to digest: "); PrintBytes(all_size, all); printf("\n");
    printf("Siv-Encrypt, after GetDigest: "); PrintBytes(Aes::BLOCKBYTESIZE, iv_); printf("\n");
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
  Cmac cmac(128);

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
    first_size -= Aes::BLOCKBYTESIZE;
  }
  last_size = all_size - first_size;

  cmac.AddToHash(first_size, all);
  cmac.Final(last_size, &all[first_size]);

#ifdef DEBUG
    printf("Siv-Decrypt, to digest: "); PrintBytes(all_size, all); printf("\n");
    printf("Siv-Decrypt, after GetDigest: "); PrintBytes(Aes::BLOCKBYTESIZE, iv_); printf("\n");
    printf("\n");
#endif

  free(all);
  all = nullptr;

  byte computed_iv[16];
  if (!cmac.GetDigest(Aes::BLOCKBYTESIZE, computed_iv)) {
    LOG(ERROR) << "AesSiv::Decrypt: GetDigest fails\n";
    return false;
  }

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
