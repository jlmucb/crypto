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

PolyGcmMult::PolyGcmMult() {
}

PolyGcmMult::~PolyGcmMult() {
}

bool PolyGcmMult::MultPoly(uint64_t* a, uint64_t* b, uint64_t* c) {
  return true;
}

bool PolyGcmMult::Reduce(uint64_t* a) {
  return true;
}

bool PolyGcmMult::MultAndReduce(uint64_t* a, uint64_t* b, uint64_t* c) {
  return true;
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
            int size_A, int size_iv, byte* iv, bool use_aesni) {
  use_aesni_ = use_aesni;
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

void AesGcm::GHashInit(int size_H, uint64_t* H) {
}

void AesGcm::GHashAddBlock(uint64_t* X) {
}

void AesGcm::GHashAdd(int size, uint64_t* X) {
}

void AesGcm::GCtrInit(int size_key, uint64_t* key, int size_iv, uint64_t* iv) {
}

void AesGcm::GCtrAddBlock(uint64_t* X, uint64_t* Y) {
}

void AesGcm::GCtrAdd(uint64_t* X, uint64_t* Y, int size) {
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
