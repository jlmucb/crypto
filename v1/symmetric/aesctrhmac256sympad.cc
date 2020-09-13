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
// File: aescbchmac256sympad.cc

#include "cryptotypes.h"
#include "util.h"
#include "conversions.h"
#include "symmetric_cipher.h"
#include "encryption_algorithm.h"
#include "aes.h"
#include "sha256.h"
#include "hmac_sha256.h"
#include "aesctrhmac256sympad.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>

AesCtrHmac256Sympad::AesCtrHmac256Sympad() {
  alg_name_ = new string("aes128-ctr-hmacsha256-sympad");
  message_id_ = nullptr;
  num_unprocessed_input_bytes_ = 0;
  input_bytes_processed_ = 0;
  output_bytes_produced_ = 0;
  iv_processed_ = false;
  memset(ctr_blk_, 0, Aes::BLOCKBYTESIZE);
  memset(hmac_received_, 0, HmacSha256::MACBYTESIZE);
  memset(hmac_computed_, 0, HmacSha256::MACBYTESIZE);
  output_verified_ = false;
  use_aesni_ = false;
}

AesCtrHmac256Sympad::~AesCtrHmac256Sympad() {
  if (alg_name_ != nullptr) {
    delete alg_name_;
    alg_name_ = nullptr;
  }
  if (message_id_ != nullptr) {
    delete message_id_;
    message_id_ = nullptr;
  }
  initialized_ = false;
}

bool AesCtrHmac256Sympad::Init(int size_enc, byte* enc_key, int size_int,
                               byte* int_key, int size_nonce, byte* nonce,
                               int size_iv, byte* iv, bool use_aesni) {
  use_aesni_ = use_aesni;
  if (size_nonce != 4) {
    LOG(ERROR) << "AesCtrHmac256Sympad::Init: bad nonce size " << size_nonce
               << "\n";
    return false;
  }
  if (size_iv != 8) {
    LOG(ERROR) << "AesCtrHmac256Sympad::Init: bad iv size " << size_iv << "\n";
    return false;
  }
  memset(iv_, 0, sizeof(iv_));
  memcpy(iv_, nonce, size_nonce);
  memcpy(&iv_[size_nonce], iv, size_iv);
  memcpy(ctr_blk_, iv_, size_iv + size_nonce);
  alg_name_ = new string("aes128-ctr-hmacsha256-sympad");
  if (use_aesni) {
    if (!aesni_obj_.Init(size_enc * NBITSINBYTE, enc_key,
                         SymmetricCipher::ENCRYPT)) {
      LOG(ERROR) << "AesCtrHmac256Sympad::Init: can't init aesni_obj_\n";
      return false;
    }
  } else {
    if (!aes_obj_.Init(size_enc * NBITSINBYTE, enc_key,
                       SymmetricCipher::ENCRYPT)) {
      LOG(ERROR) << "AesCtrHmac256Sympad::Init: can't init aes_obj_\n";
      return false;
    }
  }
  if (!hmac_.Init(size_int, int_key)) {
    LOG(ERROR) << "AesCtrHmac256Sympad::Init: can't init hmac\n";
    return false;
  }
  output_verified_ = false;
  num_unprocessed_input_bytes_ = 0;
  ctr_ = (unsigned*)&ctr_blk_[12];
  *ctr_ = 0;
  initialized_ = true;
  return true;
}

bool AesCtrHmac256Sympad::FinalPlainIn(int size_in, byte* in, int* size_out,
                                       byte* out) {
  // process all but partial final block
  int num_out = *size_out;
  int num_full = (size_in / Aes::BLOCKBYTESIZE) * Aes::BLOCKBYTESIZE;

  if (!PlainIn(num_full, in, &num_out, out)) {
    LOG(ERROR) << "PlainIn failed\n";
    return false;
  }
  out += num_out;
  in += num_full;
  size_in -= num_full;

  if (size_in > 0) {
    CtrEncryptBlock(in, out, size_in);
    hmac_.AddToInnerHash(size_in, out);
    in += size_in;
    out += size_in;
    output_bytes_produced_ += size_in;
    input_bytes_processed_ += size_in;
  }

  if (*size_out < (num_out + HmacSha256::MACBYTESIZE)) {
    LOG(ERROR) << "PlainIn output buffer is too small, size_out: " << *size_out
               << ", num_out: " << num_out << "\n";
    return false;
  }
  hmac_.Final();
  hmac_.GetHmac(HmacSha256::MACBYTESIZE, hmac_computed_);
  memcpy(out, hmac_computed_, HmacSha256::MACBYTESIZE);
  output_bytes_produced_ += HmacSha256::MACBYTESIZE;
  *size_out = num_out + size_in + HmacSha256::MACBYTESIZE;
  return true;
}

bool AesCtrHmac256Sympad::FinalCipherIn(int size_in, byte* in, int* size_out,
                                        byte* out) {
  int k = HmacSha256::MACBYTESIZE;
  int num_full_bytes;
  int num_out = *size_out;

  num_full_bytes = ((size_in - k) / Aes::BLOCKBYTESIZE) * Aes::BLOCKBYTESIZE;
  if (size_in < k) {
    LOG(ERROR) << "FinalCipherIn failed\n";
    return false;
  }

  // process all but final block and hmac
  if (!CipherIn(num_full_bytes, in, &num_out, out)) {
    LOG(ERROR) << "FinalCipherIn: CipherIn failed\n";
    return false;
  }
  out += num_out;
  in += num_full_bytes;
  size_in -= num_full_bytes + k;

  // decrypt and mac final ciphertext
  CtrDecryptBlock(in, out, size_in);
  hmac_.AddToInnerHash(size_in, in);
  in += size_in;
  out += size_in;

  input_bytes_processed_ += size_in;
  output_bytes_produced_ += size_in;
  memcpy(hmac_received_, in, k);
  input_bytes_processed_ += k;

  // compute hmac
  hmac_.Final();
  hmac_.GetHmac(HmacSha256::MACBYTESIZE, hmac_computed_);

  *size_out = num_full_bytes + size_in;

  // verify it is the same as the received one
  output_verified_ =
      (memcmp(hmac_received_, hmac_computed_, HmacSha256::MACBYTESIZE) == 0);
  return true;
}

bool AesCtrHmac256Sympad::ProcessFinalInput(int size_in, byte* in,
                                            int* size_out, byte* out) {
  if (direction_ == EncryptionAlgorithm::ENCRYPT) {
    return FinalPlainIn(size_in, in, size_out, out);
  } else if (direction_ == EncryptionAlgorithm::DECRYPT) {
    return FinalCipherIn(size_in, in, size_out, out);
  } else {
    return false;
  }
}

void AesCtrHmac256Sympad::CtrEncryptBlock(byte* in, byte* out, int shortblock) {
  byte toencrypt[2 * Aes::BLOCKBYTESIZE];

  (*ctr_)++;
  if (use_aesni_) {
    aesni_obj_.EncryptBlock(ctr_blk_, toencrypt);
  } else {
    aes_obj_.EncryptBlock(ctr_blk_, toencrypt);
  }
  for (int i = 0; i < shortblock; i++) out[i] = toencrypt[i] ^ in[i];
  hmac_.AddToInnerHash(shortblock, out);
}

void AesCtrHmac256Sympad::CtrDecryptBlock(byte* in, byte* out, int shortblock) {
  byte toencrypt[2 * Aes::BLOCKBYTESIZE];

  if (shortblock <= 0) return;
  hmac_.AddToInnerHash(shortblock, in);
  (*ctr_)++;
  if (use_aesni_) {
    aesni_obj_.EncryptBlock(ctr_blk_, toencrypt);
  } else {
    aes_obj_.EncryptBlock(ctr_blk_, toencrypt);
  }
  for (int i = 0; i < shortblock; i++) out[i] = toencrypt[i] ^ in[i];
}

bool AesCtrHmac256Sympad::PlainIn(int size_in, byte* in, int* size_out,
                                  byte* out) {
  int n;
  int num_iv = 0;
  int num_out = 0;

  if (!iv_processed_) {
    iv_processed_ = true;
    memcpy(out, ctr_blk_, Aes::BLOCKBYTESIZE);
    out += Aes::BLOCKBYTESIZE;
    num_iv = Aes::BLOCKBYTESIZE;
  }
  if (num_unprocessed_input_bytes_ > 0) {
    if ((num_unprocessed_input_bytes_ + size_in) < Aes::BLOCKBYTESIZE) {
      memcpy(&input_buf[num_unprocessed_input_bytes_], in, size_in);
      num_unprocessed_input_bytes_ += num_unprocessed_input_bytes_;
      *size_out = 0;
      return true;
    } else {
      n = Aes::BLOCKBYTESIZE - num_unprocessed_input_bytes_;
      memcpy(&input_buf[num_unprocessed_input_bytes_], in, n);
      size_in -= n;
      in += n;
      num_unprocessed_input_bytes_ = 0;
      CtrEncryptBlock(input_buf, out, Aes::BLOCKBYTESIZE);
      num_out += Aes::BLOCKBYTESIZE;
      out += Aes::BLOCKBYTESIZE;
    }
  }
  while (size_in >= Aes::BLOCKBYTESIZE) {
    CtrEncryptBlock(in, out, Aes::BLOCKBYTESIZE);
    num_out += Aes::BLOCKBYTESIZE;
    in += Aes::BLOCKBYTESIZE;
    out += Aes::BLOCKBYTESIZE;
    size_in -= Aes::BLOCKBYTESIZE;
  }
  if (size_in > 0) {
    memcpy(input_buf, in, size_in);
    num_unprocessed_input_bytes_ = size_in;
  }
  *size_out = num_out + num_iv;
  output_bytes_produced_ += *size_out;
  input_bytes_processed_ += num_out;
  return true;
}

bool AesCtrHmac256Sympad::CipherIn(int size_in, byte* in, int* size_out,
                                   byte* out) {
  int num_out = 0;
  int num_iv = 0;

  if ((size_in % Aes::BLOCKBYTESIZE) != 0) {
    LOG(ERROR) << "CipherIn: not multiple of AES BLOCKSIZE " << size_in << "\n";
    return false;
  }

  if (!iv_processed_) {
    iv_processed_ = true;
    memcpy(ctr_blk_, in, Aes::BLOCKBYTESIZE);
    in += Aes::BLOCKBYTESIZE;
    num_iv = Aes::BLOCKBYTESIZE;
    size_in -= Aes::BLOCKBYTESIZE;
  }

  while (size_in >= Aes::BLOCKBYTESIZE) {
    CtrDecryptBlock(in, out, Aes::BLOCKBYTESIZE);
    num_out += Aes::BLOCKBYTESIZE;
    in += Aes::BLOCKBYTESIZE;
    out += Aes::BLOCKBYTESIZE;
    size_in -= Aes::BLOCKBYTESIZE;
  }
  *size_out = num_out;
  input_bytes_processed_ += num_out + num_iv;
  output_bytes_produced_ += num_out;
  return true;
}

bool AesCtrHmac256Sympad::ProcessInput(int size_in, byte* in, int* size_out,
                                       byte* out) {
  if (!initialized_) return false;
  if (direction_ == EncryptionAlgorithm::ENCRYPT) {
    return PlainIn(size_in, in, size_out, out);
  } else if (direction_ == EncryptionAlgorithm::DECRYPT) {
    return CipherIn(size_in, in, size_out, out);
  } else {
    return false;
  }
}

void AesCtrHmac256Sympad::PrintEncryptionAlgorithm() {
  if (message_id_ != nullptr) {
    printf("message id: %s\n", message_id_->c_str());
  }
  if (strcmp(alg_name_->c_str(), "aes128-ctr-hmacsha256-sympad") != 0) {
    printf("Unknown encryption algorithm\n");
    return;
  }
  printf("aes128-ctr-hmacsha256-sympad\n");
  if (use_aesni_) {
    printf("using aesni\n");
    aesni_obj_.PrintSymmetricKey();
  } else {
    aes_obj_.PrintSymmetricKey();
    printf("not using aesni\n");
  }
#ifdef DEBUG
  printf("hmac-key: ");
  PrintBytes(HmacSha256::BLOCKBYTESIZE, hmac_.key_);
  printf("\n");
  printf("ctr_blk : ");
  PrintBytes(Aes::BLOCKBYTESIZE, ctr_blk_);
  printf("\n");
#endif
}

int AesCtrHmac256Sympad::DecryptInputQuantum() { return Aes::BLOCKBYTESIZE; }

int AesCtrHmac256Sympad::EncryptInputQuantum() { return 1; }

int AesCtrHmac256Sympad::MaxAdditionalOutput() { return Aes::BLOCKBYTESIZE; }

int AesCtrHmac256Sympad::MaxAdditionalFinalOutput() {
  return 4 * Aes::BLOCKBYTESIZE;
}

int AesCtrHmac256Sympad::MinimumFinalDecryptIn() {
  return HmacSha256::MACBYTESIZE;
}

int AesCtrHmac256Sympad::MinimumFinalEncryptIn() { return 1; }

int AesCtrHmac256Sympad::InputBytesProcessed() {
  return input_bytes_processed_;
}

int AesCtrHmac256Sympad::OutputBytesProduced() {
  return output_bytes_produced_;
}

bool AesCtrHmac256Sympad::MessageValid() { return output_verified_; }

int AesCtrHmac256Sympad::GetComputedMac(int size, byte* out) {
  if (size < HmacSha256::MACBYTESIZE) {
    return -1;
  }
  memcpy(out, hmac_computed_, HmacSha256::MACBYTESIZE);
  return HmacSha256::MACBYTESIZE;
}

int AesCtrHmac256Sympad::GetReceivedMac(int size, byte* out) {
  if (size < HmacSha256::MACBYTESIZE) {
    return -1;
  }
  memcpy(out, hmac_received_, HmacSha256::MACBYTESIZE);
  return HmacSha256::MACBYTESIZE;
}

bool AesCtrHmac256Sympad::GenerateScheme(const char* name, int num_bits) {
  byte enc_key[64];
  byte int_key[64];
  byte nonce[4];
  byte iv[8];

  if (num_bits != 128 && num_bits != 256) {
    LOG(ERROR) << "AesCtrHmac256Sympad::GenerateScheme: unsupported key size\n";
    return false;
  }
  if (!GetCryptoRand(Aes::BLOCKBYTESIZE * NBITSINBYTE, int_key)) {
    LOG(ERROR) << "GenerateScheme: can't get key bits\n";
    return false;
  }
  if (!GetCryptoRand(HmacSha256::BLOCKBYTESIZE * NBITSINBYTE, enc_key)) {
    LOG(ERROR) << "GenerateScheme: can't get key bits\n";
    return false;
  }
  if (!GetCryptoRand(4 * NBITSINBYTE, nonce)) {
    LOG(ERROR) << "GenerateScheme: can't get nonce bits\n";
    return false;
  }
  if (!GetCryptoRand(8 * NBITSINBYTE, iv)) {
    LOG(ERROR) << "GenerateScheme: can't get iv bits\n";
    return false;
  }
  return MakeScheme(name, num_bits, enc_key, int_key, nonce, iv);
}

bool AesCtrHmac256Sympad::MakeScheme(const char* id, int num_bits,
                                     byte* enc_key, byte* int_key, byte* nonce,
                                     byte* iv) {
  message_id_ = new string(id);
  return Init(num_bits / NBITSINBYTE, enc_key, num_bits / NBITSINBYTE, int_key,
              4, nonce, 8, iv, false);
}
