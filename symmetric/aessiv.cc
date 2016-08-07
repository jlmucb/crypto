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
 *  Gen(K)
 *  L = E_K(0^b)
 *  if (msb(L) == 0) K_1 = L <<1; else K_1 = L1<<1 ^ (R1 || R0)
 *  if (msb(k1) ==0) K2 = K1 << 1 else K2 = (K1<<1) ^ (R1||R0)
 *  return K1, K2
 *
 *  SIV-Encrypt[H1,...,Ht, K1, K2](M)
 *  if t ≥ n−1 return error
 *  IV ← CMAC(H1,...,Ht,M)
 *  C ← CTR[K2](IV,M)
 *  return IV || C
 *
 *  CMAC(M1,...,Mm)
 *    n = ceil(mlen/blen)
 *    M = M1 || M2 || ... || M(n-1) || Mn*
 *    C0 = 0^b
 *    if M_n* is complete M_n = M_n* ^ K1 else M_n = M_n*||0 ^ K2
 *    for (i=1, i<n i++) C_i = E_K(C_(i-1) ^ M_i);
 *    T = msb_(tlen)(Cn)
 *    return T
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
 *  CMAC
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


Cmac::Cmac(int num_bits) { num_out_bytes_ = num_bits / NBITSINBYTE; }

Cmac::~Cmac() {}

bool Cmac::Init() {
  if (num_out_bytes_ > BLOCKBYTESIZE) return false;
  memset((byte*)state_, 0, sizeof(state_));
  num_bytes_waiting_ = 0;
  num_bits_processed_ = 0;
  finalized_ = false;
  return true;
}

void Cmac::AddToHash(int size, const byte* in) {
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
}

bool Cmac::GetDigest(int size, byte* out) {
  if (!finalized_) return false;
  if (size < num_out_bytes_) return false;
  memcpy(out, digest_, num_out_bytes_);
  return true;
}

/*
// padding
    memcpy(temp, in, (size_t)inlen);
    temp[inlen++]= 1;
    memset(temp+inlen, 0, RSizeBytes-(size_t)inlen);
    temp[RSizeBytes-1]|= 0x80;
*/

void Cmac::Final() {
  bytes_waiting_[num_bytes_waiting_++] = 0x1;
  memset(&bytes_waiting_[num_bytes_waiting_], 0,
         BLOCKBYTESIZE - num_bytes_waiting_);
  bytes_waiting_[BLOCKBYTESIZE - 1] |= 0x80;
  TransformBlock((const uint64_t*)bytes_waiting_,
                 BLOCKBYTESIZE / sizeof(uint64_t));
  memset(digest_, 0, 128);
  memcpy(digest_, state_, num_out_bytes_);
  finalized_ = true;
}