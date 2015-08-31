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
#include "ghash.h"
#include "aesgcm.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>

GAesCtr::GAesCtr() {
  use_aesni_ = false;
  size_partial_ = 0;
}

GAesCtr::~GAesCtr() {
}

bool GAesCtr::Init(int size_iv, byte* iv, int bit_size_K, byte* K,
                   int direction, bool use_aesni) {
  if (bit_size_K != 128)
    return false;

  // initialize iv and key
  direction_ = direction;
  use_aesni_ = use_aesni;
  memcpy(last_ctr_, iv, size_iv);
  memcpy(iv_, iv, size_iv);

  uint64_t x =  last_ctr_[1];
  uint64_t y;
  ReverseCpy(8, (byte*)&x, (byte*)&y);
  y++;
  ReverseCpy(8, (byte*)&y, (byte*)&last_ctr_[1]);

  size_partial_ = 0;
  memset(partial_, 0, 16);
  if (use_aesni_) {
    if (!aesni_.Init(128, K, Aes::ENCRYPT))
      return false;
  } else {
    if (!aes_.Init(128, K, Aes::ENCRYPT))
      return false;
  }
  return true;
}

void GAesCtr::EncryptBlock(uint64_t* in, uint64_t* out) {
  uint64_t t[2];

  if (use_aesni_)
    aesni_.EncryptBlock((byte*)last_ctr_, (byte*)t);
  else
    aes_.EncryptBlock((byte*)last_ctr_, (byte*)t);
  for (int i = 0; i < 2; i++) {
    out[i] = in[i] ^ t[i];
  }

  uint64_t x =  last_ctr_[1];
  uint64_t y;
  ReverseCpy(8, (byte*)&x, (byte*)&y);
  y++;
  ReverseCpy(8, (byte*)&y, (byte*)&last_ctr_[1]);
}

void GAesCtr::DecryptBlock(uint64_t* in, uint64_t* out) {
  EncryptBlock(in, out);
}

void GAesCtr::Encrypt(int size, byte* in, byte* out) {
  byte* next = in;

  if (size_partial_ > 0) {
    if ((size_partial_ + size) >= 16) {
      int n = 16 - size_partial_;
      memcpy(next, &partial_[size_partial_], n);
      EncryptBlock((uint64_t*)partial_, (uint64_t*)out);
      size_partial_ = 0;
      memset(partial_, 0, 16);
      next += n;
      size -= n;
      out += n;
    } else {
      memcpy(partial_, &partial_[size_partial_], size);
      size_partial_ += size;
      return;
    }
  }

  while (size >= 16) {
    EncryptBlock((uint64_t*)next, (uint64_t*)out);
    next += 16;
    out += 16;
    size -= 16;
  }
  if (size > 0) {
    memcpy(partial_, next, size);
    size_partial_ = size;
  }
}

void GAesCtr::Decrypt(int size, byte* in, byte* out) {
  Encrypt(size, in, out);
}

bool GAesCtr::GetCtr(byte* out) {
  memcpy(out, last_ctr_, 16);
  return true;
}

AesGcm::AesGcm() {
  alg_name_ = new string("aes128-gcm128");
  message_id_ = nullptr;
  memset(received_tag_, 0, 16);
  output_verified_ = false;
}

AesGcm::~AesGcm() {
  initialized_ = false;
  if (alg_name_ != nullptr) {
    delete alg_name_;
    alg_name_ = nullptr;
  }
  initialized_ = false;
}

bool AesGcm::Init(int bit_size_key, byte* key, int size_tag,
                  int size_iv, byte* iv, int direction,
                  bool use_aesni) {
  Aes aes;
  AesNi aesni;
  byte zero[16];
  byte H[16];
  memset(zero, 0, 16);

  if (!aesctr_.Init(size_iv, iv, bit_size_key, key,
                    direction, use_aesni)) {
    return false;
  }
  if (use_aesni) {
    if (!aesni.Init(128, key, AesNi::ENCRYPT)) {
      LOG(ERROR) << "AesGcm::Init, aesni.Init failed";
      return false;
    }
   aesni.EncryptBlock(zero, H);
     aesni.EncryptBlock(iv, (byte*)encrypted_iv_);
  } else {
    if (!aes.Init(128, key, Aes::ENCRYPT)) {
      LOG(ERROR) << "AesGcm::Init, aesni.Init failed";
      return false;
    }
   aes.EncryptBlock(zero, H);
   aes.EncryptBlock(iv, (byte*)encrypted_iv_);
  }
  ghash_.Init(H);
  size_tag_ = size_tag;
  direction_ = direction;
  initialized_ = true;
  return true;
}

bool AesGcm::AuthenticatedIn(int size_in, byte* in) {
  ghash_.AddAHash(size_in, in);
  return true;
}

bool AesGcm::FinalAuthenticatedIn(int size_in, byte* in) {
  ghash_.FinalA();
  return true;
}

bool AesGcm::FinalPlainIn(int size_in, byte* in, int* size_out,
                          byte* out) {
  if (size_in > 0)
    PlainIn(size_in, in, size_out, out);
  ghash_.FinalC();
  return true;
}

bool AesGcm::PlainIn(int size_in, byte* in, int* size_out,
                     byte* out) {
  aesctr_.Encrypt(size_in, in, out);
  ghash_.AddCHash(size_in, out);
  *size_out = size_in;
  return true;
}

bool AesGcm::FinalCipherIn(int size_in, byte* in, int* size_out,
                           byte* out) {
  CipherIn(size_in, in, size_out, out);
  ghash_.FinalC();
  return true;
}

bool AesGcm::CipherIn(int size_in, byte* in, int* size_out,
                      byte* out) {
  aesctr_.Decrypt(size_in, in, out);
  ghash_.AddCHash(size_in, in);
  *size_out = size_in;
  return true;
}

void AesGcm::PrintEncryptionAlgorithm() {
  if (alg_name_ == nullptr) {
    printf("No encryption algorithm\n");
    return;
  }
  if (message_id_ != nullptr) {
    printf("message id: %s\n", message_id_->c_str());
  }
  if (*alg_name_ != "aes128-gcm128") {
    printf("Unknown encryption algorithm\n");
    return;
  }
  printf("aes128-gcm128\n");
  if (UseNi()) {
    printf("using aesni\n");
    GetAesNi()->PrintSymmetricKey();
  } else {
    GetAes()->PrintSymmetricKey();
    printf("not using aesni\n");
  }
  printf("iv      : ");
  PrintBytes(Aes::BLOCKBYTESIZE, GetIv());
  printf("\n");
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

bool AesGcm::MessageValid() {
  if (output_verified_)
    return true;
  byte tag[16];
  if (!GetComputedTag(16, tag))
    return false;
  if (memcmp(received_tag_, tag, 16) == 0) {
    output_verified_ = true;
    return true;
  } else {
    return false;
  }
}

int AesGcm::GetComputedTag(int size, byte* out) {
  uint64_t the_hash[2];
  ghash_.GetHash(the_hash);

  uint64_t final[2];
  final[0] = the_hash[0] ^ encrypted_iv_[0];
  final[1] = the_hash[1] ^ encrypted_iv_[1];
  memcpy(out, (byte*)final, 16);
  return size;
}

int AesGcm::SetReceivedTag(int size, byte* in) {
  memcpy(received_tag_, in, 16);
  return 0;
}

bool AesGcm::GenerateScheme(const char* name, int num_bits) {
  byte enc_key[64];
  byte iv[64];

  if (num_bits != 128 && num_bits != 256) {
    LOG(ERROR) << "AesGcm::GenerateScheme: unsupported key size\n";
    return false;
  }
  if (!GetCryptoRand(12 * NBITSINBYTE, iv)) {
    LOG(ERROR) << "GenerateScheme: can't get key bits\n";
    return false;
  }
  if (!GetCryptoRand(Aes::BLOCKBYTESIZE * NBITSINBYTE, enc_key)) {
    LOG(ERROR) << "GenerateScheme: can't get key bits\n";
    return false;
  }
  return MakeScheme(name, num_bits, enc_key, iv);
}

bool AesGcm::MakeScheme(const char* id, int num_bits,
                        byte* enc_key, byte* iv) {
  if (!aesctr_.Init(96, iv, num_bits, enc_key, 
                    Aes::ENCRYPT, false)) {
    LOG(ERROR) << "AesGcm::MakeScheme: Init fails\n";
    return false;
  }

  alg_name_ = new string("aes128-gcm128");
  message_id_ = new string(id);
  initialized_ = true;
  return true;
}
