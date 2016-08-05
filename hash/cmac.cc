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
// File: sha3.cc

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
 *  Algorithm SIV-EncryptH1,...,Ht (M)
 *  if t ≥ n−1 then return error
 *  IV ← CMAC∗ (H1,...,Ht,M)
 *  C ← CTRK2(IV,M)
 *  return IV || C
 *
 *  AlgorithmCMAC∗ (X1,...,Xm)
 *  S ← CMACK(0^n)
 *  fori←1tom−1doS←dbl(S)⊕CMACK(Xi)
 *  if |Xm| ≥ n return CMACK (S ^end Xm) else return CMACK (dbl(S) ^ Xm10*)
 *
 *  Algorithm CTRK(IV,M)
 *  Ctr←IV & 1^(n−64) 01^31 01^31
 *  Pad ← EK(Ctr) EK(Ctr+1) EK(Ctr+2) ···
 *  return M ^ Pad [1..|M |]
 *
 *  Algorithm SIV-DecryptH1,...,Ht (C)
 *   t ≥ n−1 or |C| < n then return error
 *  V ← C[1..n],
 *  C ← [n + 1..|C|]
 *  M ← CTRK2(IV, C)
 *  IV' ← CMAC∗ (H1,...,Ht,M)
 *  if IV = IV' then return M else return error
 */

/*
 Input:
   Key: fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0
        f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff
   AD: 10111213 14151617 18191a1b 1c1d1e1f
       20212223 24252627
   Plaintext: 11223344 55667788 99aabbcc ddee

   S2V-CMAC-AES

   CMAC(zero): 0e04dfaf c1efbf04 01405828 59bf073a
   double(): 1c09bf5f 83df7e08 0280b050 b37e0e74
   CMAC(ad): f1f922b7 f5193ce6 4ff80cb4 7d93f23b
   xor: edf09de8 76c642ee 4d78bce4 ceedfc4f
   double(): dbe13bd0 ed8c85dc 9af179c9 9ddbf819
   pad: 11223344 55667788 99aabbcc ddee8000
   xor: cac30894 b8eaf254 035bc205 40357819
   CMAC(final): 85632d07 c6e8f37f 950acd32 0a2ecc93

   CTR-AES

   CTR: 85632d07 c6e8f37f 150acd32 0a2ecc93
   E(K,CTR): 51e218d2 c5a2ab8c 4345c4a6 23b2f08f
   ciphertext: 40c02b96 90c4dc04 daef7f6a fe5c
   output: 85632d07 c6e8f37f 950acd32 0a2ecc93 40c02b96 90c4dc04 daef7f6a fe5c
 */


Cmac::Cmac(int num_bits) { num_out_bytes_ = num_bits / NBITSINBYTE; }

Cmac::~Cmac() {}

bool Cmac::Init() {
  // aes_
  // L = E_K(0^b)
  // if (msb(L) == 0) K_1 = L <<1; else K_1 = L1<<1 ^ (R1 || R0)
  // n = ceil(mlen/blen)
  // M = M1 || M2 || ... || M(n-1) || Mn*
  // C0 = 0^b
  // if M_n* is complete M_n = M_n* ^ K1 else M_n = M_n*||0 ^ K2
  // for (i=1, i<n i++) C_i = E_K(c_(i-1) ^ M_i;
  // T = msb_(tlen)(Cn)
  // return T
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
