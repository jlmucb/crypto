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
// File: aescbchmac256sympad.cc

#include "cryptotypes.h"
#include "util.h"
#include "conversions.h"
#include "symmetric_cipher.h"
#include "encryption_algorithm.h"
#include "aes.h"
#include "sha256.h"
#include "hmac_sha256.h"
#include "aescbchmac256sympad.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>

AesCbcHmac256Sympad::AesCbcHmac256Sympad() {
  alg_name_ = new string("aes128-cbc-hmacsha256-sympad");
  message_id_ = nullptr;
  num_unprocessed_input_bytes_ = 0;
  input_bytes_processed_ = 0;
  output_bytes_produced_ = 0;
  iv_processed_ = false;
  memset(iv_, 0, Aes::BLOCKBYTESIZE);
  memset(last_cipher_block_, 0, Aes::BLOCKBYTESIZE);
  memset(hmac_received_, 0, HmacSha256::MACBYTESIZE);
  memset(hmac_computed_, 0, HmacSha256::MACBYTESIZE);
  output_verified_ = false;
  use_aesni_ = false;
}

AesCbcHmac256Sympad::~AesCbcHmac256Sympad() {
  if (alg_name_ != nullptr) {
    delete alg_name_;
    alg_name_ = nullptr;
  }
  initialized_ = false;
}

bool AesCbcHmac256Sympad::InitEnc(int size_enc, byte* enc_key, int size_int,
                                  byte* int_key, int size_iv, byte* iv,
                                  bool use_aesni) {
  alg_name_ = new string("aes128-cbc-hmacsha256-sympad");
  use_aesni_ = use_aesni;
  if (size_iv != Aes::BLOCKBYTESIZE) {
    return false;
  }
  memcpy(iv_, iv, size_iv);
  memcpy(last_cipher_block_, iv, size_iv);
  if (use_aesni) {
    if (!aesni_obj_.Init(size_enc * NBITSINBYTE, enc_key,
                         SymmetricCipher::ENCRYPT)) {
      return false;
    }
  } else {
    if (!aes_obj_.Init(size_enc * NBITSINBYTE, enc_key,
                       SymmetricCipher::ENCRYPT)) {
      return false;
    }
  }
  if (!hmac_.Init(size_int, int_key)) {
    return false;
  }
  output_verified_ = false;
  num_unprocessed_input_bytes_ = 0;
  direction_ = EncryptionAlgorithm::ENCRYPT;
  initialized_ = true;
  return true;
}

bool AesCbcHmac256Sympad::InitDec(int size_enc, byte* enc_key, int size_int,
                                  byte* int_key, bool use_aesni) {
  alg_name_ = new string("aes128-cbc-hmacsha256-sympad");
  use_aesni_ = use_aesni;
  if (use_aesni) {
    if (!aesni_obj_.Init(size_enc * NBITSINBYTE, enc_key,
                         SymmetricCipher::DECRYPT)) {
      return false;
    }
  } else {
    if (!aes_obj_.Init(size_enc * NBITSINBYTE, enc_key,
                       SymmetricCipher::DECRYPT)) {
      return false;
    }
  }
  if (!hmac_.Init(size_int, int_key)) {
    return false;
  }
  output_verified_ = false;
  num_unprocessed_input_bytes_ = 0;
  direction_ = EncryptionAlgorithm::DECRYPT;
  iv_processed_ = false;
  initialized_ = true;
  return true;
}

bool AesCbcHmac256Sympad::FinalPlainIn(int size_in, byte* in, int* size_out,
                                       byte* out) {
  // process all but partial final block
  int num_out = *size_out;
  if (!PlainIn(size_in, in, &num_out, out)) {
    LOG(ERROR) << "PlainIn failed\n";
    return false;
  }
  out += num_out;
  if (*size_out < (num_out + Aes::BLOCKBYTESIZE + HmacSha256::MACBYTESIZE)) {
    LOG(ERROR) << "PlainIn output buffer is too small, size_out: " << *size_out
               << ", num_out: " << num_out << "\n";
    return false;
  }
  // all that's left is pad block
  int n = num_unprocessed_input_bytes_;
  input_buf[num_unprocessed_input_bytes_++] = 0x80;
  memset(&input_buf[num_unprocessed_input_bytes_], 0,
         Aes::BLOCKBYTESIZE - num_unprocessed_input_bytes_);
  CbcEncryptBlock(input_buf, out);
  out += Aes::BLOCKBYTESIZE;
  // compute hmac
  hmac_.Final();
  hmac_.GetHmac(HmacSha256::MACBYTESIZE, hmac_computed_);
  memcpy(out, hmac_computed_, HmacSha256::MACBYTESIZE);
  output_bytes_produced_ += Aes::BLOCKBYTESIZE + HmacSha256::MACBYTESIZE;
  input_bytes_processed_ += n;
  *size_out = num_out + Aes::BLOCKBYTESIZE + HmacSha256::MACBYTESIZE;
  return true;
}

bool AesCbcHmac256Sympad::FinalCipherIn(int size_in, byte* in, int* size_out,
                                        byte* out) {
  int num_out = *size_out;
  int k = Aes::BLOCKBYTESIZE + HmacSha256::MACBYTESIZE;
  int n = 0;

  if (size_in < k || (size_in % Aes::BLOCKBYTESIZE) != 0) {
    LOG(ERROR) << "FinalCipherIn failed\n";
    return false;
  }

  // process all but final block and hmac
  if (size_in > k) {
    if (!CipherIn(size_in - k, in, &num_out, out)) {
      LOG(ERROR) << "FinalCipherIn: CipherIn failed\n";
      return false;
    }
    out += num_out;
    in += size_in - k;
  }

  // decrypt final ciphertext and depad
  byte padded[Aes::BLOCKBYTESIZE];
  CbcDecryptBlock(in, padded);
  for (n = (Aes::BLOCKBYTESIZE - 1); n >= 0; n--) {
    if (padded[n] == 0x80)
      break;
    if (padded[n] != 0) {
      LOG(ERROR) << "FinalCipherIn: bad pad\n";
      return false;
    }
  }
  in += Aes::BLOCKBYTESIZE;
  memcpy(out, padded, n);
  memcpy(hmac_received_, in, HmacSha256::MACBYTESIZE);

  // compute hmac
  hmac_.Final();
  hmac_.GetHmac(HmacSha256::MACBYTESIZE, hmac_computed_);

  output_bytes_produced_ += n;
  input_bytes_processed_ += Aes::BLOCKBYTESIZE + HmacSha256::MACBYTESIZE;
  *size_out = num_out + n;
  // verify it is the same as the received one
  output_verified_ =
      (memcmp(hmac_received_, hmac_computed_, HmacSha256::MACBYTESIZE) == 0);
  return true;
}

bool AesCbcHmac256Sympad::ProcessFinalInput(int size_in, byte* in,
                                            int* size_out, byte* out) {
  if (direction_ == EncryptionAlgorithm::ENCRYPT) {
    return FinalPlainIn(size_in, in, size_out, out);
  } else if (direction_ == EncryptionAlgorithm::DECRYPT) {
    return FinalCipherIn(size_in, in, size_out, out);
  } else {
    return false;
  }
}

void AesCbcHmac256Sympad::CbcEncryptBlock(byte* in, byte* out) {
  byte toencrypt[2 * Aes::BLOCKBYTESIZE];

  for (int i = 0; i < Aes::BLOCKBYTESIZE; i++)
    toencrypt[i] = last_cipher_block_[i] ^ in[i];
  if (use_aesni_) {
    aesni_obj_.EncryptBlock(toencrypt, out);
  } else {
    aes_obj_.EncryptBlock(toencrypt, out);
  }
  hmac_.AddToInnerHash(Aes::BLOCKBYTESIZE, out);
  memcpy(last_cipher_block_, out, Aes::BLOCKBYTESIZE);
}

void AesCbcHmac256Sympad::CbcDecryptBlock(byte* in, byte* out) {
  byte decrypted[2 * Aes::BLOCKBYTESIZE];

  hmac_.AddToInnerHash(Aes::BLOCKBYTESIZE, in);
  if (use_aesni_) {
    aesni_obj_.DecryptBlock(in, decrypted);
  } else {
    aes_obj_.DecryptBlock(in, decrypted);
  }
  for (int i = 0; i < Aes::BLOCKBYTESIZE; i++)
    out[i] = last_cipher_block_[i] ^ decrypted[i];
  memcpy(last_cipher_block_, in, Aes::BLOCKBYTESIZE);
}

bool AesCbcHmac256Sympad::PlainIn(int size_in, byte* in, int* size_out,
                                  byte* out) {
  int n;
  int num_iv = 0;
  int num_out = 0;

  if (!iv_processed_) {
    iv_processed_ = true;
    memcpy(out, last_cipher_block_, Aes::BLOCKBYTESIZE);
    out += Aes::BLOCKBYTESIZE;
    num_iv = Aes::BLOCKBYTESIZE;
  }
  if (num_unprocessed_input_bytes_ > 0) {
    if ((num_unprocessed_input_bytes_ + size_in) < Aes::BLOCKBYTESIZE) {
      memcpy(&input_buf[num_unprocessed_input_bytes_], in, size_in);
      num_unprocessed_input_bytes_ += size_in;
      *size_out = 0;
      return true;
    } else {
      n = Aes::BLOCKBYTESIZE - num_unprocessed_input_bytes_;
      memcpy(&input_buf[num_unprocessed_input_bytes_], in, n);
      size_in -= n;
      in += n;
      num_unprocessed_input_bytes_ = 0;
      CbcEncryptBlock(input_buf, out);
      num_out += Aes::BLOCKBYTESIZE;
      out += Aes::BLOCKBYTESIZE;
    }
  }
  while (size_in >= Aes::BLOCKBYTESIZE) {
    CbcEncryptBlock(in, out);
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

bool AesCbcHmac256Sympad::CipherIn(int size_in, byte* in, int* size_out,
                                   byte* out) {
  int num_out = 0;
  int num_iv = 0;

  if ((size_in % Aes::BLOCKBYTESIZE) != 0) {
    LOG(ERROR) << "CipherIn: not multiple of AES BLOCKSIZE " << size_in << "\n";
    return false;
  }

  if (!iv_processed_) {
    memcpy(last_cipher_block_, in, Aes::BLOCKBYTESIZE);
    in += Aes::BLOCKBYTESIZE;
    num_iv = Aes::BLOCKBYTESIZE;
    size_in -= Aes::BLOCKBYTESIZE;
    iv_processed_ = true;
    num_iv = Aes::BLOCKBYTESIZE;
  }

  while (size_in >= Aes::BLOCKBYTESIZE) {
    CbcDecryptBlock(in, out);
    num_out += Aes::BLOCKBYTESIZE;
    in += Aes::BLOCKBYTESIZE;
    out += Aes::BLOCKBYTESIZE;
    size_in -= Aes::BLOCKBYTESIZE;
  }
  *size_out = num_out;
  output_bytes_produced_ += num_out;
  input_bytes_processed_ += num_iv + num_iv;
  return true;
}

bool AesCbcHmac256Sympad::ProcessInput(int size_in, byte* in, int* size_out,
                                       byte* out) {
  if (!initialized_)
    return false;
  if (direction_ == EncryptionAlgorithm::ENCRYPT) {
    return PlainIn(size_in, in, size_out, out);
  } else if (direction_ == EncryptionAlgorithm::DECRYPT) {
    return CipherIn(size_in, in, size_out, out);
  } else {
    return false;
  }
}

void AesCbcHmac256Sympad::PrintEncryptionAlgorithm() {
  if (alg_name_ == nullptr) {
    printf("No encryption algorithm\n");
    return;
  }
  if (message_id_ != nullptr) {
    printf("message id: %s\n", message_id_->c_str());
  }
  if (strcmp(alg_name_->c_str(), "aes128-cbc-hmacsha256-sympad") != 0) {
    printf("Unknown encryption algorithm\n");
    return;
  }
  printf("aes128-cbc-hmacsha256-sympad\n");
  if (use_aesni_) {
    printf("using aesni\n");
    aesni_obj_.PrintSymmetricKey();
  } else {
    aes_obj_.PrintSymmetricKey();
    printf("not using aesni\n");
  }
  printf("hmac-key: ");
  PrintBytes(HmacSha256::BLOCKBYTESIZE, hmac_.key_);
  printf("\n");
  printf("iv      : ");
  PrintBytes(Aes::BLOCKBYTESIZE, iv_);
  printf("\n");
}

int AesCbcHmac256Sympad::DecryptInputQuantum() { return Aes::BLOCKBYTESIZE; }

int AesCbcHmac256Sympad::EncryptInputQuantum() { return 1; }

int AesCbcHmac256Sympad::MaxAdditionalOutput() { return Aes::BLOCKBYTESIZE; }

int AesCbcHmac256Sympad::MaxAdditionalFinalOutput() {
  return 4 * Aes::BLOCKBYTESIZE;
}

int AesCbcHmac256Sympad::MinimumFinalDecryptIn() {
  return 4 * Aes::BLOCKBYTESIZE;
}

int AesCbcHmac256Sympad::MinimumFinalEncryptIn() { return 1; }

int AesCbcHmac256Sympad::InputBytesProcessed() {
  return input_bytes_processed_;
}

int AesCbcHmac256Sympad::OutputBytesProduced() {
  return output_bytes_produced_;
}

bool AesCbcHmac256Sympad::MessageValid() { return output_verified_; }

int AesCbcHmac256Sympad::GetComputedMac(int size, byte* out) {
  if (size < HmacSha256::MACBYTESIZE) {
    return -1;
  }
  memcpy(out, hmac_computed_, HmacSha256::MACBYTESIZE);
  return HmacSha256::MACBYTESIZE;
}

int AesCbcHmac256Sympad::GetReceivedMac(int size, byte* out) {
  if (size < HmacSha256::MACBYTESIZE) {
    return -1;
  }
  memcpy(out, hmac_received_, HmacSha256::MACBYTESIZE);
  return HmacSha256::MACBYTESIZE;
}

bool AesCbcHmac256Sympad::GenerateScheme(const char* name, int num_bits) {
  byte enc_key[64];
  byte int_key[64];
  byte iv[64];

  if (num_bits != 128 && num_bits != 256) {
    LOG(ERROR) << "AesCbcHmac256Sympad::GenerateScheme: unsupported key size\n";
    return false;
  }
  if (!GetCryptoRand(Aes::BLOCKBYTESIZE * NBITSINBYTE, iv)) {
    LOG(ERROR) << "GenerateScheme: can't get key bits\n";
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
  return MakeScheme(name, num_bits, enc_key, int_key, iv);
}

bool AesCbcHmac256Sympad::MakeScheme(const char* id, int num_bits,
                                     byte* enc_key, byte* int_key, byte* iv) {
  if (!hmac_.Init(HmacSha256::BLOCKBYTESIZE, int_key)) {
    LOG(ERROR) << "AesCbcHmac256Sympad::MakeScheme: hmac_Init fails\n";
    return false;
  }
  if (!aes_obj_.Init(128, enc_key, SymmetricCipher::BOTH)) {
    LOG(ERROR) << "AesCbcHmac256Sympad::MakeScheme: aes_obj_.Init fails\n";
    return false;
  }
  if (!aesni_obj_.Init(128, int_key, SymmetricCipher::BOTH)) {
    LOG(ERROR) << "AesCbcHmac256Sympad::MakeScheme: aesni_obj_.Init fails\n";
    return false;
  }

  alg_name_ = new string("aes128-cbc-hmacsha256-sympad");
  message_id_ = new string(id);
  memcpy(iv_, iv, Aes::BLOCKBYTESIZE);
  use_aesni_ = false;
  initialized_ = true;
  return true;
}
