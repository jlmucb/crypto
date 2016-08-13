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

#define DEBUG

static bool CalcIv(byte* K, int hdr_size, byte* hdr_in, int msg_size, byte* msg_in, byte* out) {

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

  dbl(S, X);

#ifdef DEBUG
  printf("\n");
  printf("K        : "); PrintBytes(16, K); printf("\n");
  printf("hdr      : "); PrintBytes(16, hdr_in); printf("\n");
  printf("msg      : "); PrintBytes(16, msg_in); printf("\n");
  printf("First S  : "); PrintBytes(16, S); printf("\n");
  printf("Should be: 0e04dfafc1efbf040140582859bf073a\n");
  printf("dbl(X)   : "); PrintBytes(16, X); printf("\n");
  printf("Should be: 1c09bf5f83df7e080280b050b37e0e74\n");
  printf("\n");
#endif

  cmac.Init(K);
  int first_hdr_size = (hdr_size / Aes::BLOCKBYTESIZE) * Aes::BLOCKBYTESIZE;
  int last_hdr_size;
  if (first_hdr_size == hdr_size)
    first_hdr_size -= Aes::BLOCKBYTESIZE;
  last_hdr_size = hdr_size - first_hdr_size;
  cmac.AddToHash(first_hdr_size, hdr_in);
  cmac.Final(last_hdr_size, (byte*)&hdr_in[first_hdr_size]);
  cmac.GetDigest(Aes::BLOCKBYTESIZE, Y); 
  Xor(Y, X, S, Aes::BLOCKBYTESIZE);

#ifdef DEBUG
  printf("\n");
  printf("Cmac hdr : "); PrintBytes(16, Y); printf("\n");
  printf("Should be: f1f922b7f5193ce64ff80cb47d93f23b\n");
  printf("S        : "); PrintBytes(16, S); printf("\n");
  printf("\n");
#endif

  // last Xn
  dbl(S, X);
  cmac.Init(K);
  int first_msg_size = (msg_size / Aes::BLOCKBYTESIZE) * Aes::BLOCKBYTESIZE;
  int last_msg_size;
  if (first_msg_size == msg_size)
    first_msg_size -= Aes::BLOCKBYTESIZE;
  last_msg_size = msg_size - first_msg_size;
  if (msg_size >= Aes::BLOCKBYTESIZE) {
    int num_blocks = first_msg_size / Aes::BLOCKBYTESIZE;
    for (int i = 0; i < num_blocks; i++) {
      Xor(&msg_in[i * Aes::BLOCKBYTESIZE], S, T, Aes::BLOCKBYTESIZE);
      cmac.AddToHash(Aes::BLOCKBYTESIZE, T);
printf("msg      : "); PrintBytes(16, &msg_in[i * Aes::BLOCKBYTESIZE]); printf("\n");
printf("S        : "); PrintBytes(16, S); printf("\n");
printf("Add      : "); PrintBytes(16, T); printf("\n");
    }
    memset(T, 0, Aes::BLOCKBYTESIZE);
    Xor(&msg_in[num_blocks * Aes::BLOCKBYTESIZE], S, T, last_msg_size);
    cmac.Final(last_msg_size, T);
printf("Final    : "); PrintBytes(16, T); printf("\n");
  } else {
    memset(Y, 0, Aes::BLOCKBYTESIZE);
    memcpy(Y, msg_in, msg_size);
    Y[last_msg_size]= 0x80;
    Xor(X, Y, T, Aes::BLOCKBYTESIZE);
    cmac.Final(Aes::BLOCKBYTESIZE, T);
printf("msg      : "); PrintBytes(16, Y); printf("\n");
printf("X        : "); PrintBytes(16, X); printf("\n");
printf("Final    : "); PrintBytes(16, T); printf("\n");
  }
  cmac.GetDigest(Aes::BLOCKBYTESIZE, out); 

#ifdef DEBUG
  printf("out      : "); PrintBytes(16, out); printf("\n");
  printf("\n");
#endif
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

  if (!CalcIv(K1_, hdr_size, hdr, msg_size, msg, iv_)) {
    LOG(ERROR) << "AesSiv::Encrypt: CalcIv fails\n";
    return false;
  }

#ifdef DEBUG
    printf("\n");
    printf("Siv-Encrypt hdr: "); PrintBytes(hdr_size, hdr); printf("\n");
    printf("Siv-Encrypt msg: "); PrintBytes(msg_size, msg); printf("\n");
    printf("Siv-Encrypt, iv: "); PrintBytes(Aes::BLOCKBYTESIZE, iv_); printf("\n");
    printf("\n");
#endif

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

  byte computed_iv[16];

  if (!CalcIv(K1_, hdr_size, hdr, *size_out, out, computed_iv)) {
    LOG(ERROR) << "AesSiv::Encrypt: CalcIv fails\n";
    return false;
  }

#ifdef DEBUG
    printf("\n");
    printf("Siv-Decrypt hdr: "); PrintBytes(hdr_size, hdr); printf("\n");
    printf("Siv-Decrypt cipher: "); PrintBytes(cipher_size, cipher); printf("\n");
    printf("Siv-Decrypt, calculated iv: "); PrintBytes(Aes::BLOCKBYTESIZE, computed_iv); printf("\n");
    printf("\n");
#endif

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
