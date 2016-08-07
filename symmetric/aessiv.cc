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

/*
 *  SIV-Encrypt[H1,...,Ht, K1, K2](M)
 *  if t ≥ n−1 return error
 *  IV ← CMAC[K1](H1,...,Ht,M)
 *  C ← CTR[K2](IV,M)
 *  return IV || C
 *
 *  CTR[K](IV,M)
 *  Ctr ← IV & 1^(n−64) 01^31 01^31
 *  Pad ← E[K](Ctr)|| E[K](Ctr+1)||E[K](Ctr+2) ···
 *  return M ^ Pad [1..|M |]
 *
 *  SIV-Decrypt[H1,...,Ht, K1, K2](C)
 *  t ≥ n−1 or |C| < n return error
 *  V ← C[1..n],
 *  C ← [n + 1..|C|]
 *  M ← CTRK2(IV, C)
 *  IV' ← CMAC∗ (H1,...,Ht,M)
 *  if IV = IV' return M else return error
 */

/*
 * Key: fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0
 *      f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff
 * AD: 10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627
 * Plaintext: 11223344 55667788 99aabbcc ddee
 *
 * S2V-CMAC-AES
 *
 * CMAC(zero): 0e04dfaf c1efbf04 01405828 59bf073a
 * double(): 1c09bf5f 83df7e08 0280b050 b37e0e74
 * CMAC(ad): f1f922b7 f5193ce6 4ff80cb4 7d93f23b
 * xor: edf09de8 76c642ee 4d78bce4 ceedfc4f
 * double(): dbe13bd0 ed8c85dc 9af179c9 9ddbf819
 * pad: 11223344 55667788 99aabbcc ddee8000
 * xor: cac30894 b8eaf254 035bc205 40357819
 * CMAC(final): 85632d07 c6e8f37f 950acd32 0a2ecc93
 *
 * CTR-AES
 *
 * CTR: 85632d07 c6e8f37f 150acd32 0a2ecc93
 * E(K,CTR): 51e218d2 c5a2ab8c 4345c4a6 23b2f08f
 * ciphertext: 40c02b96 90c4dc04 daef7f6a fe5c
 * output: 85632d07 c6e8f37f 950acd32 0a2ecc93 40c02b96 90c4dc04 daef7f6a fe5c
 */

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

/*
 *  SIV-Encrypt[H1,...,Ht, K1, K2](M)
 *  if t ≥ n−1 return error
 *  IV ← CMAC[K1](H1,...,Ht,M)
 *  C ← CTR[K2](IV,M)
 *  return IV || C
 *
 *  CTR[K](IV,M)
 *  Ctr ← IV & 1^(n−64) 01^31 01^31
 *  Pad ← E[K](Ctr)|| E[K](Ctr+1)||E[K](Ctr+2) ···
 *  return M ^ Pad [1..|M |]
 */
bool AesSiv::Encrypt(byte* K, int hdr_size, byte* hdr, int msg_size, byte* msg, int* size_out, byte*out) {
  Cmac cmac(128);

  if (!ComputeSubKeys(K)) return false;
  if (cmac.Init(K1_)) return false;
  int all_size = hdr_size + msg_size;
  byte* all = (byte*)malloc(all_size);
  if (all == nullptr) return false;
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
  if (!cmac.GetDigest(Aes::BLOCKBYTESIZE, iv_)) return false;
  // Now encrypt with counter mode with key, K2 and ctr initialized to IV & 1^(n−64) 01^31 01^31
  // out = iv_ || C
  return true;
}

bool AesSiv::Decrypt(byte* K, int hdr_size, byte* hdr, int msg_size, byte* msg, int* size_out, byte* out) {
  // Now decrypt with counter mode with key, K2 and ctr initialized to IV & 1^(n−64) 01^31 01^31
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
