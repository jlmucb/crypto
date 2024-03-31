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

#include "crypto_support.h"
#include "hash.h"
#include "sha3.h"

// This implementation assumes a little-endian platform.

#define ROL(a, offset)                             \
  ((((uint64_t)a) << ((offset) % NBITSINUINT64)) ^ \
   (((uint64_t)a) >> (NBITSINUINT64 - ((offset) % NBITSINUINT64))))

const uint64_t KeccakF_RoundConstants[sha3::NR] = {
    (uint64_t)0x0000000000000001ULL, (uint64_t)0x0000000000008082ULL,
    (uint64_t)0x800000000000808aULL, (uint64_t)0x8000000080008000ULL,
    (uint64_t)0x000000000000808bULL, (uint64_t)0x0000000080000001ULL,
    (uint64_t)0x8000000080008081ULL, (uint64_t)0x8000000000008009ULL,
    (uint64_t)0x000000000000008aULL, (uint64_t)0x0000000000000088ULL,
    (uint64_t)0x0000000080008009ULL, (uint64_t)0x000000008000000aULL,
    (uint64_t)0x000000008000808bULL, (uint64_t)0x800000000000008bULL,
    (uint64_t)0x8000000000008089ULL, (uint64_t)0x8000000000008003ULL,
    (uint64_t)0x8000000000008002ULL, (uint64_t)0x8000000000000080ULL,
    (uint64_t)0x000000000000800aULL, (uint64_t)0x800000008000000aULL,
    (uint64_t)0x8000000080008081ULL, (uint64_t)0x8000000000008080ULL,
    (uint64_t)0x0000000080000001ULL, (uint64_t)0x8000000080008008ULL};

sha3::sha3() {};

sha3::~sha3() {}

void sha3::transform_block(const uint64_t* in, int laneCount) {
  int round;
  uint64_t Aba, Abe, Abi, Abo, Abu;
  uint64_t Aga, Age, Agi, Ago, Agu;
  uint64_t Aka, Ake, Aki, Ako, Aku;
  uint64_t Ama, Ame, Ami, Amo, Amu;
  uint64_t Asa, Ase, Asi, Aso, Asu;
  uint64_t BCa, BCe, BCi, BCo, BCu;
  uint64_t Da, De, Di, Do, Du;
  uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
  uint64_t Ega, Ege, Egi, Ego, Egu;
  uint64_t Eka, Eke, Eki, Eko, Eku;
  uint64_t Ema, Eme, Emi, Emo, Emu;
  uint64_t Esa, Ese, Esi, Eso, Esu;

  while ((--laneCount) >= 0) state_[laneCount] ^= in[laneCount];

#if 1
  printf("After xor\n");
  print_bytes(200, (byte*)state_);
  printf("\n");
#endif

  // copyFromState(A, state)
  Aba = state_[0];
  Abe = state_[1];
  Abi = state_[2];
  Abo = state_[3];
  Abu = state_[4];
  Aga = state_[5];
  Age = state_[6];
  Agi = state_[7];
  Ago = state_[8];
  Agu = state_[9];
  Aka = state_[10];
  Ake = state_[11];
  Aki = state_[12];
  Ako = state_[13];
  Aku = state_[14];
  Ama = state_[15];
  Ame = state_[16];
  Ami = state_[17];
  Amo = state_[18];
  Amu = state_[19];
  Asa = state_[20];
  Ase = state_[21];
  Asi = state_[22];
  Aso = state_[23];
  Asu = state_[24];

  for (round = 0; round < NR; round += 2) {
    // prepareTheta
    BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
    BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
    BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
    BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
    BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

    // thetaRhoPiChiIotaPrepareTheta(round, A, E)
    Da = BCu ^ ROL(BCe, 1);
    De = BCa ^ ROL(BCi, 1);
    Di = BCe ^ ROL(BCo, 1);
    Do = BCi ^ ROL(BCu, 1);
    Du = BCo ^ ROL(BCa, 1);

    Aba ^= Da;
    BCa = Aba;
    Age ^= De;
    BCe = ROL(Age, 44);
    Aki ^= Di;
    BCi = ROL(Aki, 43);
    Amo ^= Do;
    BCo = ROL(Amo, 21);
    Asu ^= Du;
    BCu = ROL(Asu, 14);
    Eba = BCa ^ ((~BCe) & BCi);
    Eba ^= (uint64_t)KeccakF_RoundConstants[round];
    Ebe = BCe ^ ((~BCi) & BCo);
    Ebi = BCi ^ ((~BCo) & BCu);
    Ebo = BCo ^ ((~BCu) & BCa);
    Ebu = BCu ^ ((~BCa) & BCe);

    Abo ^= Do;
    BCa = ROL(Abo, 28);
    Agu ^= Du;
    BCe = ROL(Agu, 20);
    Aka ^= Da;
    BCi = ROL(Aka, 3);
    Ame ^= De;
    BCo = ROL(Ame, 45);
    Asi ^= Di;
    BCu = ROL(Asi, 61);
    Ega = BCa ^ ((~BCe) & BCi);
    Ege = BCe ^ ((~BCi) & BCo);
    Egi = BCi ^ ((~BCo) & BCu);
    Ego = BCo ^ ((~BCu) & BCa);
    Egu = BCu ^ ((~BCa) & BCe);

    Abe ^= De;
    BCa = ROL(Abe, 1);
    Agi ^= Di;
    BCe = ROL(Agi, 6);
    Ako ^= Do;
    BCi = ROL(Ako, 25);
    Amu ^= Du;
    BCo = ROL(Amu, 8);
    Asa ^= Da;
    BCu = ROL(Asa, 18);
    Eka = BCa ^ ((~BCe) & BCi);
    Eke = BCe ^ ((~BCi) & BCo);
    Eki = BCi ^ ((~BCo) & BCu);
    Eko = BCo ^ ((~BCu) & BCa);
    Eku = BCu ^ ((~BCa) & BCe);

    Abu ^= Du;
    BCa = ROL(Abu, 27);
    Aga ^= Da;
    BCe = ROL(Aga, 36);
    Ake ^= De;
    BCi = ROL(Ake, 10);
    Ami ^= Di;
    BCo = ROL(Ami, 15);
    Aso ^= Do;
    BCu = ROL(Aso, 56);
    Ema = BCa ^ ((~BCe) & BCi);
    Eme = BCe ^ ((~BCi) & BCo);
    Emi = BCi ^ ((~BCo) & BCu);
    Emo = BCo ^ ((~BCu) & BCa);
    Emu = BCu ^ ((~BCa) & BCe);

    Abi ^= Di;
    BCa = ROL(Abi, 62);
    Ago ^= Do;
    BCe = ROL(Ago, 55);
    Aku ^= Du;
    BCi = ROL(Aku, 39);
    Ama ^= Da;
    BCo = ROL(Ama, 41);
    Ase ^= De;
    BCu = ROL(Ase, 2);
    Esa = BCa ^ ((~BCe) & BCi);
    Ese = BCe ^ ((~BCi) & BCo);
    Esi = BCi ^ ((~BCo) & BCu);
    Eso = BCo ^ ((~BCu) & BCa);
    Esu = BCu ^ ((~BCa) & BCe);

    // prepareTheta
    BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
    BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
    BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
    BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
    BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

    // thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
    Da = BCu ^ ROL(BCe, 1);
    De = BCa ^ ROL(BCi, 1);
    Di = BCe ^ ROL(BCo, 1);
    Do = BCi ^ ROL(BCu, 1);
    Du = BCo ^ ROL(BCa, 1);

    Eba ^= Da;
    BCa = Eba;
    Ege ^= De;
    BCe = ROL(Ege, 44);
    Eki ^= Di;
    BCi = ROL(Eki, 43);
    Emo ^= Do;
    BCo = ROL(Emo, 21);
    Esu ^= Du;
    BCu = ROL(Esu, 14);
    Aba = BCa ^ ((~BCe) & BCi);
    Aba ^= (uint64_t)KeccakF_RoundConstants[round + 1];
    Abe = BCe ^ ((~BCi) & BCo);
    Abi = BCi ^ ((~BCo) & BCu);
    Abo = BCo ^ ((~BCu) & BCa);
    Abu = BCu ^ ((~BCa) & BCe);

    Ebo ^= Do;
    BCa = ROL(Ebo, 28);
    Egu ^= Du;
    BCe = ROL(Egu, 20);
    Eka ^= Da;
    BCi = ROL(Eka, 3);
    Eme ^= De;
    BCo = ROL(Eme, 45);
    Esi ^= Di;
    BCu = ROL(Esi, 61);
    Aga = BCa ^ ((~BCe) & BCi);
    Age = BCe ^ ((~BCi) & BCo);
    Agi = BCi ^ ((~BCo) & BCu);
    Ago = BCo ^ ((~BCu) & BCa);
    Agu = BCu ^ ((~BCa) & BCe);

    Ebe ^= De;
    BCa = ROL(Ebe, 1);
    Egi ^= Di;
    BCe = ROL(Egi, 6);
    Eko ^= Do;
    BCi = ROL(Eko, 25);
    Emu ^= Du;
    BCo = ROL(Emu, 8);
    Esa ^= Da;
    BCu = ROL(Esa, 18);
    Aka = BCa ^ ((~BCe) & BCi);
    Ake = BCe ^ ((~BCi) & BCo);
    Aki = BCi ^ ((~BCo) & BCu);
    Ako = BCo ^ ((~BCu) & BCa);
    Aku = BCu ^ ((~BCa) & BCe);

    Ebu ^= Du;
    BCa = ROL(Ebu, 27);
    Ega ^= Da;
    BCe = ROL(Ega, 36);
    Eke ^= De;
    BCi = ROL(Eke, 10);
    Emi ^= Di;
    BCo = ROL(Emi, 15);
    Eso ^= Do;
    BCu = ROL(Eso, 56);
    Ama = BCa ^ ((~BCe) & BCi);
    Ame = BCe ^ ((~BCi) & BCo);
    Ami = BCi ^ ((~BCo) & BCu);
    Amo = BCo ^ ((~BCu) & BCa);
    Amu = BCu ^ ((~BCa) & BCe);

    Ebi ^= Di;
    BCa = ROL(Ebi, 62);
    Ego ^= Do;
    BCe = ROL(Ego, 55);
    Eku ^= Du;
    BCi = ROL(Eku, 39);
    Ema ^= Da;
    BCo = ROL(Ema, 41);
    Ese ^= De;
    BCu = ROL(Ese, 2);
    Asa = BCa ^ ((~BCe) & BCi);
    Ase = BCe ^ ((~BCi) & BCo);
    Asi = BCi ^ ((~BCo) & BCu);
    Aso = BCo ^ ((~BCu) & BCa);
    Asu = BCu ^ ((~BCa) & BCe);
  }

  // copyToState(state, A)
  state_[0] = Aba;
  state_[1] = Abe;
  state_[2] = Abi;
  state_[3] = Abo;
  state_[4] = Abu;
  state_[5] = Aga;
  state_[6] = Age;
  state_[7] = Agi;
  state_[8] = Ago;
  state_[9] = Agu;
  state_[10] = Aka;
  state_[11] = Ake;
  state_[12] = Aki;
  state_[13] = Ako;
  state_[14] = Aku;
  state_[15] = Ama;
  state_[16] = Ame;
  state_[17] = Ami;
  state_[18] = Amo;
  state_[19] = Amu;
  state_[20] = Asa;
  state_[21] = Ase;
  state_[22] = Asi;
  state_[23] = Aso;
  state_[24] = Asu;
}

bool sha3::init(int c, int num_bits_out) {
  num_out_bytes_ = num_bits_out / NBITSINBYTE;
  c_ = c;
  cb_ = c_ / NBITSINBYTE;
  r_ = b_ - c;
  rb_ = r_ / NBITSINBYTE;
  if (num_out_bytes_ > BLOCKBYTESIZE) return false;
  memset(bytes_waiting_, 0, BUFFERBYTESIZE);
  for (int i = 0; i < 25; i++)
    state_[i] = 0ULL;
  num_bytes_waiting_ = 0;
  num_bits_processed_ = 0;
  finalized_ = false;
  return true;
}

void sha3::add_to_hash(int size, const byte* in) {
  if (num_bytes_waiting_ > 0) {
    int needed = rb_ - num_bytes_waiting_;
    if (size < needed) {
      memcpy(&bytes_waiting_[num_bytes_waiting_], in, size);
      num_bytes_waiting_ += size;
      return;
    }
    memcpy(&bytes_waiting_[num_bytes_waiting_], in, needed);
    transform_block((const uint64_t*)bytes_waiting_,
                   rb_ / sizeof(uint64_t));
#if 1
  printf("After transform\n");
  print_bytes(200, (byte*)state_);
  printf("\n");
#endif
    num_bits_processed_ += rb_ * NBITSINBYTE;
    size -= needed;
    in += needed;
    num_bytes_waiting_ = 0;
  }
  while (size >= rb_) {
    transform_block((const uint64_t*)in, rb_ / sizeof(uint64_t));
#if 1
  printf("After transform\n");
  print_bytes(200, (byte*)state_);
  printf("\n");
#endif
    num_bits_processed_ += rb_ * NBITSINBYTE;
    size -= rb_;
    in += rb_;
  }
  if (size > 0) {
    num_bytes_waiting_ = size;
    memcpy(bytes_waiting_, in, size);
  }
}

bool sha3::get_digest(int size, byte* out) {
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

// for sha-3, add bitstring 11 to message plus pad
void sha3::finalize() {
  bytes_waiting_[num_bytes_waiting_++] = 0x07;
  num_bits_processed_ += 2;
  memset(&bytes_waiting_[num_bytes_waiting_], 0,
         rb_ - num_bytes_waiting_);
  int k = rb_ - 1;
  bytes_waiting_[rb_ - 1] |= 0x80;
  transform_block((const uint64_t*)bytes_waiting_,
                 rb_ / sizeof(uint64_t));
#if 1
  printf("After transform\n");
  print_bytes(200, (byte*)state_);
  printf("\n");
#endif
  num_bytes_waiting_ = 0;
  memset(digest_, 0, 128);
  memcpy(digest_, state_, num_out_bytes_);
  finalized_ = true;
}

// for shake, add bitstring 1111 to message plus pad
void sha3::shake_finalize() {
  bytes_waiting_[num_bytes_waiting_++] = 0x1f;
  memset(&bytes_waiting_[num_bytes_waiting_], 0,
         rb_ - num_bytes_waiting_);
  bytes_waiting_[rb_ - 1] |= 0x80;
  transform_block((const uint64_t*)bytes_waiting_,
                 rb_ / sizeof(uint64_t));
#if 1
  printf("After transform\n");
  print_bytes(200, (byte*)state_);
  printf("\n");
#endif
  num_bytes_waiting_ = 0;
  memset(digest_, 0, 128);
  memcpy(digest_, state_, num_out_bytes_);
  finalized_ = true;
}
