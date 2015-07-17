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
// Project: New Cloudproxy Crypto
// File: aesgcm.cc

#include "cryptotypes.h"
#include "util.h"
#include "conversions.h"
#include "symmetric_cipher.h"
#include "encryption_algorithm.h"
#include "aes.h"
#include "aesgcm.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>

bool MultPoly(int size_a, uint64_t* a, int size_b, uint64_t* b,
              int size_c, uint64_t* c) {
  return true;
}

bool Reduce(int size_a, uint64_t* a, int size_p, uint64_t* min_poly) {
  return true;
}

bool MultAndReduce(int size_a, uint64_t* a, int size_b, uint64_t* b,
                   int size_p, uint64_t* min_poly, int size_c, uint64_t* c) {
  return true;
}

Ghash::Ghash(uint64_t* H) {
  // x^7+x^2+x+1
  min_poly_[0] = 0x83;
  min_poly_[1] = 0x0;
  // x^128
  min_poly_[3] = 0x1;
  memcpy(H_, H, 16);
  memset(last_x_, 0, 32);
}

Ghash::~Ghash() {
}

void Ghash::Init() {
}

void Ghash::AddToHash(int size, byte* data) {
}

void Ghash::Final() {
}

bool Ghash::GetHash(uint64_t* out)  {
  return true;
}

GAesCtr::GAesCtr() {
  use_aesni_ = false;
}

GAesCtr::~GAesCtr() {
}

void GAesCtr::Init(int size_iv, uint64_t* iv, int size_K, byte* K) {
  // initialize iv and key
}

void GAesCtr::NextBlock(uint64_t* in, uint64_t* out) {
  uint64_t t[2];

  if (use_aesni_)
    aesni_.EncryptBlock((byte*)last_ctr_, (byte*)t);
  else
    aes_.EncryptBlock((byte*)last_ctr_, (byte*)t);
  for (int i = 0; i < 2; i++) {
    in[i] = out[i] ^ t[i];
  }
  (*ctr_)++;
}

AesGcm::AesGcm() {
  alg_name_ = new string("aes128-gcm128");
}

AesGcm::~AesGcm() {
  initialized_ = false;
  if (alg_name_ != nullptr) {
    delete alg_name_;
    alg_name_ = nullptr;
  }
  initialized_ = false;
}

bool AesGcm::Init(int size_key, byte*, int size_block, int size_tag,
            int size_A, int size_C, int size_iv, byte* iv, bool use_aesni) {
  use_aesni_ = use_aesni;
  byte zero[16];
  memset(zero, 0, 16);
  // aesni_.EncryptBlock(zero, (byte*)H_);
  // s = 128*ceiling(size_iv/128) - size_iv
  // J = GHash(iv || 0 || size_iv_64)
  // u = 128*ceiling(len(C)/128) - len(C)
  // v = 128*ceiling(len(A)/128) - len())
  // S Ghash_H(A || O^v ||| C || 0^u || len(A)_64 || len(c)_64)
  // T =  MSB_t(GCtr(J, S))
  // return (C, T)
  initialized_ = true;
  return true;
}

bool AesGcm::FinalPlainIn(int size_in, byte* in, int* size_out,
                          byte* out) {
  return true;
}

bool AesGcm::FinalCipherIn(int size_in, byte* in, int* size_out,
                           byte* out) {
  return true;
}

bool AesGcm::ProcessFinalInput(int size_in, byte* in,
                               int* size_out, byte* out) {
  return true;
}

void AesGcm::GcmEncryptBlock(byte* in, byte* out) {
}

void AesGcm::GcmDecryptBlock(byte* in, byte* out) {
}

bool AesGcm::AuthenticatedIn(int size_in, byte* in, int* size_out, byte* out) {
  return true;
}

bool AesGcm::FinalAuthenticatedIn(int size_in, byte* in, int* size_out, byte* out) {
  return true;
}

bool AesGcm::PlainIn(int size_in, byte* in, int* size_out,
                     byte* out) {
  return true;
}

bool AesGcm::CipherIn(int size_in, byte* in, int* size_out,
                      byte* out) {
  return true;
}

bool AesGcm::ProcessInput(int size_in, byte* in, int* size_out,
                          byte* out) {
  if (!initialized_) return false;
  return true;
}

void AesGcm::PrintEncryptionAlgorithm() {
  if (strcmp(alg_name_->c_str(), "aes128-gcm128") != 0) {
    printf("Unknown encryption algorithm\n");
    return;
  }
  printf("aes128-gcm128\n");
  if (use_aesni_) {
    printf("using aesni\n");
    aesni_obj_.PrintSymmetricKey();
  } else {
    aes_obj_.PrintSymmetricKey();
    printf("not using aesni\n");
  }
}

int AesGcm::DecryptInputQuantum() { return Aes::BLOCKBYTESIZE; }

int AesGcm::EncryptInputQuantum() { return 1; }

int AesGcm::MaxAdditionalOutput() { return Aes::BLOCKBYTESIZE; }

int AesGcm::MaxAdditionalFinalOutput() {
  return 4 * Aes::BLOCKBYTESIZE;
}

int AesGcm::MinimumFinalDecryptIn() {
  return 1;
}

int AesGcm::MinimumFinalEncryptIn() { return 1; }

int AesGcm::InputBytesProcessed() {
  return input_bytes_processed_;
}

int AesGcm::OutputBytesProduced() {
  return output_bytes_produced_;
}

bool AesGcm::MessageValid() { return output_verified_; }

int AesGcm::GetComputedTag(int size, byte* out) {
  return 0;
}

int AesGcm::GetReceivedTag(int size, byte* out) {
  return 0;
}

bool AesGcm::GenerateScheme(const char* name, int num_bits) {
  return true;
}

bool AesGcm::MakeScheme(const char* id, int num_bits,
                        byte* enc_key, byte* iv) {
  return true;
}
