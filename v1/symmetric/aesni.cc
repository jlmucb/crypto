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
//
// See README for original license from aes authors which is incorporated here
//      by reference.
// Project: New Cloudproxy Crypto
// File: aesni.cc

#include "cryptotypes.h"
#include "util.h"
#include "symmetric_cipher.h"
#include "aes.h"

AesNi::AesNi() {
  direction_ = NONE;
  cipher_name_ = nullptr;
  initialized_ = false;
  num_key_bits_ = 0;
  key_ = nullptr;
  encrypt_round_key_ = nullptr;
  decrypt_round_key_ = nullptr;
}

AesNi::~AesNi() {
  if (encrypt_round_key_ != nullptr) {
    memset(encrypt_round_key_, 0, 4 * num_rounds_ * sizeof(uint32_t));
    delete encrypt_round_key_;
    encrypt_round_key_ = nullptr;
  }
  if (decrypt_round_key_ != nullptr) {
    memset(decrypt_round_key_, 0, 4 * num_rounds_ * sizeof(uint32_t));
    delete decrypt_round_key_;
    decrypt_round_key_ = nullptr;
  }
}

// compute key schedule in encrypt direction
bool AesNi::InitEnc() {
  encrypt_round_key_ = new uint32_t[4 * (AesNi::MAXNR + 1) + 1];
  if (encrypt_round_key_ == nullptr) {
    return false;
  }
  byte* enc_key_sched = (byte*)encrypt_round_key_;
  byte* key = (byte*)key_;

  //  rdi --- key
  //  rsi --- enc_key_sched
  if (num_rounds_ == 10) {
    asm volatile(
        "\tjmp                  2f\n"
        "1: \n"
        "\tpshufd              $255, %%xmm2, %%xmm2\n"
        "\tmovdqa              %%xmm1, %%xmm3 \n"
        "\tpslldq              $4, %%xmm3 \n"
        "\tpxor                %%xmm3, %%xmm1 \n"
        "\tpslldq              $4, %%xmm3 \n"
        "\tpxor                %%xmm3, %%xmm1 \n"
        "\tpslldq              $4, %%xmm3\n"
        "\tpxor                %%xmm3, %%xmm1\n"
        "\tpxor                %%xmm2, %%xmm1\n"
        "\tret\n"
        "2:\n"
        "\tmovq                %[key], %%rdi\n"
        "\tmovq                %[enc_key_sched], %%rsi\n"
        "\tmovdqu              (%%rdi), %%xmm1 \n"
        "\tmovdqu              %%xmm1, (%%rsi)\n"
        "\taeskeygenassist     $1, %%xmm1, %%xmm2\n"
        "\tcall                1b\n"
        "\tmovdqu              %%xmm1, 16(%%rsi) \n"
        "\taeskeygenassist     $2, %%xmm1, %%xmm2 \n"
        "\tcall                1b\n"
        "\tmovdqu              %%xmm1, 32(%%rsi) \n"
        "\taeskeygenassist     $4, %%xmm1, %%xmm2 \n"
        "\tcall                1b\n"
        "\tmovdqu              %%xmm1, 48(%%rsi) \n"
        "\taeskeygenassist     $8, %%xmm1, %%xmm2 \n"
        "\tcall                1b\n"
        "\tmovdqu              %%xmm1, 64(%%rsi) \n"
        "\taeskeygenassist     $16, %%xmm1, %%xmm2 \n"
        "\tcall                1b\n"
        "\tmovdqu              %%xmm1, 80(%%rsi) \n"
        "\taeskeygenassist     $32, %%xmm1, %%xmm2 \n"
        "\tcall                1b\n"
        "\tmovdqu              %%xmm1, 96(%%rsi) \n"
        "\taeskeygenassist     $64, %%xmm1, %%xmm2 \n"
        "\tcall                1b\n"
        "\tmovdqu              %%xmm1, 112(%%rsi) \n"
        "\taeskeygenassist     $0x80, %%xmm1, %%xmm2 \n"
        "\tcall                1b\n"
        "\tmovdqu              %%xmm1, 128(%%rsi) \n"
        "\taeskeygenassist     $0x1b, %%xmm1, %%xmm2 \n"
        "\tcall                1b\n"
        "\tmovdqu              %%xmm1, 144(%%rsi) \n"
        "\taeskeygenassist     $0x36, %%xmm1, %%xmm2 \n"
        "\tcall                1b\n"
        "\tmovdqu              %%xmm1, 160(%%rsi)\n"
        :
      : [key] "m"(key), [enc_key_sched] "m"(enc_key_sched)
      : "%rdi", "%rsi", "%xmm1", "%xmm2", "%xmm3");
  } else if(num_rounds_ == 14) {
    asm volatile(
        "\tjmp                  3f\n"

        "1: \n"
        "\tpshufd              $0xff, %%xmm2, %%xmm2\n"
        "\tmovdqa              %%xmm1, %%xmm4\n"
        "\tpslldq              $4, %%xmm4 \n"
        "\tpxor                %%xmm4, %%xmm1 \n"
        "\tpslldq              $4, %%xmm4 \n"
        "\tpxor                %%xmm4, %%xmm1 \n"
        "\tpslldq              $4, %%xmm4 \n"
        "\tpxor                %%xmm4, %%xmm1 \n"
        "\tpxor                %%xmm2, %%xmm1\n"
        "\tret\n"
 
	"2:\n"
        "\tpshufd              $0xaa, %%xmm2, %%xmm2\n"
        "\tmovdqa              %%xmm3, %%xmm4\n"
        "\tpslldq              $4, %%xmm4 \n"
        "\tpxor                %%xmm4, %%xmm3 \n"
        "\tpslldq              $4, %%xmm4 \n"
        "\tpxor                %%xmm4, %%xmm3 \n"
        "\tpslldq              $4, %%xmm4 \n"
        "\tpxor                %%xmm4, %%xmm3 \n"
        "\tpxor                %%xmm2, %%xmm3\n"
        "\tret\n"

        "3:\n"
        "\tmovq                %[key], %%rdi\n"
        "\tmovq                %[enc_key_sched], %%rsi\n"
        "\tmovdqu              (%%rdi), %%xmm1 \n"
        "\tmovdqu              16(%%rdi), %%xmm3 \n"

        "\tmovdqa              %%xmm1, (%%rsi)\n"
        "\tmovdqa              %%xmm3, 16(%%rsi)\n"

        "\taeskeygenassist     $0x1, %%xmm3, %%xmm2\n"
        "\tcall                1b\n"
        "\tmovdqu              %%xmm1, 32(%%rsi) \n"
        "\taeskeygenassist     $0x0, %%xmm1, %%xmm2 \n"
        "\tcall                2b\n"
        "\tmovdqu              %%xmm3, 48(%%rsi) \n"

        "\taeskeygenassist     $0x2, %%xmm3, %%xmm2 \n"
        "\tcall                1b\n"
        "\tmovdqu              %%xmm1, 64(%%rsi) \n"
        "\taeskeygenassist     $0x0, %%xmm1, %%xmm2 \n"
        "\tcall                2b\n"
        "\tmovdqu              %%xmm3, 80(%%rsi) \n"

        "\taeskeygenassist     $0x4, %%xmm3, %%xmm2 \n"
        "\tcall                1b\n"
        "\tmovdqu              %%xmm1, 96(%%rsi) \n"
        "\taeskeygenassist     $0x0, %%xmm1, %%xmm2 \n"
        "\tcall                2b\n"
        "\tmovdqu              %%xmm3, 112(%%rsi) \n"

        "\taeskeygenassist     $0x8, %%xmm3, %%xmm2 \n"
        "\tcall                1b\n"
        "\tmovdqu              %%xmm1, 128(%%rsi) \n"
        "\taeskeygenassist     $0x0, %%xmm1, %%xmm2 \n"
        "\tcall                2b\n"
        "\tmovdqu              %%xmm3, 144(%%rsi) \n"

        "\taeskeygenassist     $0x10, %%xmm3, %%xmm2 \n"
        "\tcall                1b\n"
        "\tmovdqu              %%xmm1, 160(%%rsi) \n"
        "\taeskeygenassist     $0x0, %%xmm1, %%xmm2 \n"
        "\tcall                2b\n"
        "\tmovdqu              %%xmm3, 176(%%rsi)\n"

        "\taeskeygenassist     $0x20, %%xmm3, %%xmm2 \n"
        "\tcall                1b\n"
        "\tmovdqu              %%xmm1, 192(%%rsi)\n"
        "\taeskeygenassist     $0x0, %%xmm1, %%xmm2 \n"
        "\tcall                2b\n"
        "\tmovdqu              %%xmm3, 208(%%rsi)\n"

        "\taeskeygenassist     $0x40, %%xmm3, %%xmm2 \n"
        "\tcall                1b\n"
        "\tmovdqu              %%xmm1, 224(%%rsi)\n"
      :
      : [key] "m"(key), [enc_key_sched] "m"(enc_key_sched)
      : "%rdi", "%rsi", "%xmm1", "%xmm2", "%xmm3");
  } else {
    return false;
  }
  return true;
}

void FixAes128DecRoundKeys(byte* ks) {
  asm volatile(
      "\tmovq          %[ks], %%rdi\n"
      "\tmovdqu        (%%rdi), %%xmm1\n"
      "\taesimc        %%xmm1, %%xmm1\n"
      "\tmovdqu        %%xmm1, (%%rdi)\n"
      :
      : [ks] "m"(ks)
      : "%rdi", "%xmm1", "%xmm0");
}

bool AesNi::InitDec() {
  decrypt_round_key_ = new uint32_t[4 * (AesNi::MAXNR + 1) + 1];
  if (decrypt_round_key_ == nullptr) {
    return false;
  }
  if (encrypt_round_key_ == nullptr) {
    if (!InitEnc()) {
      return false;
    }
  }
  memcpy((byte*)decrypt_round_key_, (byte*)encrypt_round_key_,
         (4 * (AesNi::MAXNR + 1) + 1) * sizeof(uint32_t));
  if (num_rounds_ == 10) {
    for (int i = 1; i < 10; i++)
      FixAes128DecRoundKeys((byte*)&decrypt_round_key_[4 * i]);
    return true;
  } else if (num_rounds_ == 14) {
    for (int i = 1; i < 14; i++)
      FixAes128DecRoundKeys((byte*)&decrypt_round_key_[4 * i]);
    return true;
  } else {
    return false;
  }
}

void AesNi::EncryptBlock(const byte* pt, byte* ct) {
  byte* ks = (byte*)encrypt_round_key_;

  if (num_rounds_ == 10) {
    asm volatile(
        "\tmovq         %[ks], %%r8\n"
        "\tmovq         %[pt], %%rdi\n"
        "\tmovq         %[ct], %%rsi\n"
        "\tmovdqu       (%%rdi), %%xmm1\n"
        "\tmovdqu       (%%r8), %%xmm0\n"
        "\tpxor         %%xmm0, %%xmm1\n"
        "\tmovdqu       16(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       32(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       48(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       64(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       80(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       96(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       112(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       128(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       144(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       160(%%r8),%%xmm0\n"
        "\taesenclast   %%xmm0,%%xmm1\n"
        "\tmovdqu       %%xmm1,(%%rsi)\n"
        :
        : [pt] "m"(pt), [ct] "m"(ct), [ks] "m"(ks)
        : "%rdi", "%rsi", "%xmm1", "%r8", "%xmm0");
  } else {
    asm volatile(
        "\tmovq         %[ks], %%r8\n"
        "\tmovq         %[pt], %%rdi\n"
        "\tmovq         %[ct], %%rsi\n"
        "\tmovdqu       (%%rdi), %%xmm1\n"
        "\tmovdqu       (%%r8), %%xmm0\n"
        "\tpxor         %%xmm0, %%xmm1\n"
        "\tmovdqu       16(%%r8), %%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       32(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       48(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       64(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       80(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       96(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       112(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       128(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       144(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       160(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       176(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       192(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       208(%%r8),%%xmm0\n"
        "\taesenc       %%xmm0,%%xmm1\n"
        "\tmovdqu       224(%%r8),%%xmm0\n"
        "\taesenclast   %%xmm0,%%xmm1\n"
        "\tmovdqu       %%xmm1,(%%rsi)\n"
        :
        : [pt] "m"(pt), [ct] "m"(ct), [ks] "m"(ks)
        : "%rdi", "%rsi", "%xmm1", "%r8", "%xmm0");
  }
}

void AesNi::DecryptBlock(const byte* ct, byte* pt) {
  byte* ks = (byte*)decrypt_round_key_;

  if (num_rounds_ == 10) {
    asm volatile(
        "\tmovq         %[ks], %%r8\n"
        "\tmovq         %[pt], %%rdi\n"
        "\tmovq         %[ct], %%rsi\n"
        "\tmovdqu       (%%rsi), %%xmm1\n"
        "\tmovdqu       160(%%r8), %%xmm0\n"
        "\tpxor         %%xmm0, %%xmm1\n"
        "\tmovdqu       144(%%r8), %%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       128(%%r8),%%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       112(%%r8),%%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       96(%%r8),%%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       80(%%r8),%%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       64(%%r8),%%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       48(%%r8),%%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       32(%%r8),%%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       16(%%r8),%%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       (%%r8),%%xmm0\n"
        "\taesdeclast   %%xmm0,%%xmm1\n"
        "\tmovdqu       %%xmm1,(%%rdi)\n"
        :
        : [pt] "m"(pt), [ct] "m"(ct), [ks] "m"(ks)
        : "%rdi", "%rsi", "%xmm1", "%r8", "%xmm0");
  } else {
    asm volatile(
        "\tmovq         %[ks], %%r8\n"
        "\tmovq         %[pt], %%rdi\n"
        "\tmovq         %[ct], %%rsi\n"
        "\tmovdqu       (%%rsi), %%xmm1\n"
        "\tmovdqu       224(%%r8), %%xmm0\n"
        "\tpxor         %%xmm0, %%xmm1\n"
        "\tmovdqu       208(%%r8), %%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       192(%%r8), %%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       176(%%r8), %%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       160(%%r8), %%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       144(%%r8), %%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       128(%%r8),%%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       112(%%r8),%%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       96(%%r8),%%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       80(%%r8),%%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       64(%%r8),%%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       48(%%r8),%%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       32(%%r8),%%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       16(%%r8),%%xmm0\n"
        "\taesdec       %%xmm0,%%xmm1\n"
        "\tmovdqu       (%%r8),%%xmm0\n"
        "\taesdeclast   %%xmm0,%%xmm1\n"
        "\tmovdqu       %%xmm1,(%%rdi)\n"
        :
        : [pt] "m"(pt), [ct] "m"(ct), [ks] "m"(ks)
        : "%rdi", "%rsi", "%xmm1", "%r8", "%xmm0");
  }
}

bool AesNi::Init(int key_bit_size, byte* key_buf, int directionflag) {
  if (key_bit_size == 128) {
    cipher_name_ = new string("aes-128");
    num_key_bits_ = key_bit_size;
    num_rounds_ = 10;
  } else if (key_bit_size == 256) {
    cipher_name_ = new string("aes-256");
    num_key_bits_ = key_bit_size;
    num_rounds_ = 14;
  } else {
    return false;
  }
  if (key_buf == nullptr) {
    return false;
  }
  key_ = new byte[key_bit_size / NBITSINBYTE];
  if (key_ == nullptr) {
    return false;
  }
  memcpy(key_, key_buf, key_bit_size / NBITSINBYTE);
  if (directionflag == DECRYPT || directionflag == BOTH) {
    if (!InitDec()) {
      return false;
    }
  } else if (directionflag == ENCRYPT) {
    if (!InitEnc()) {
      return false;
    }
  } else {
    return false;
  }
  initialized_ = true;
  return true;
}

void AesNi::Encrypt(int in_size, byte* in, byte* out) {
  // in_size should be a multiple of block size
  while (in_size > 0) {
    EncryptBlock(in, out);
    in_size -= BLOCKBYTESIZE;
    in += BLOCKBYTESIZE;
    out += BLOCKBYTESIZE;
  }
}

void AesNi::Decrypt(int in_size, byte* in, byte* out) {
  // in_size should be a multiple of block size
  while (in_size > 0) {
    DecryptBlock(in, out);
    in_size -= BLOCKBYTESIZE;
    in += BLOCKBYTESIZE;
    out += BLOCKBYTESIZE;
  }
}
