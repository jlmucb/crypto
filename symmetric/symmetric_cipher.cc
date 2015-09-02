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
// File: symmetric_cipher.cc

#include "cryptotypes.h"
#include "util.h"
#include "aes.h"
#include "keys.pb.h"
#include "keys.h"
#include "symmetric_cipher.h"
#include "conversions.h"

SymmetricCipher::SymmetricCipher() {
  direction_ = NONE;
  cipher_name_ = nullptr;
  initialized_ = false;
  num_key_bits_ = 0;
  key_ = nullptr;
}

SymmetricCipher::~SymmetricCipher() {
  if (cipher_name_ != nullptr) {
    delete cipher_name_;
    cipher_name_ = nullptr;
  }
  initialized_ = false;
  num_key_bits_ = 0;
  if (key_ != nullptr) {
    memset(key_, 0, num_key_bits_ / NBITSINBYTE);
    delete key_;
    key_ = nullptr;
  }
}

bool SymmetricCipher::SerializeSymmetricCipherToMessage(
    crypto_symmetric_key_message& message) {
  if (cipher_name_ == nullptr) {
    LOG(ERROR) << "SerializeSymmetricCipherToMessage: no key type\n";
    return false;
  }
  if (strcmp(cipher_name_->c_str(), "aes-128") != 0) {
    LOG(ERROR) << "SerializeSymmetricCipherToMessage: unhandled alg\n";
    return false;
  }
  message.set_key_type(*cipher_name_);
  message.set_key_bit_size(128);
  string* s = ByteToBase64LeftToRight(Aes::BLOCKBYTESIZE, key_);
  if (s == nullptr) {
    LOG(ERROR) << "SerializeSymmetricCipherToMessage: can't build base64 key\n";
    return false;
  }
  message.set_value(s->c_str());
  delete s;
  return true;
}

bool SymmetricCipher::DeserializeSymmetricCipherFromMessage(
    crypto_symmetric_key_message& message) {
  if (!message.has_key_type()) {
    LOG(ERROR) << "DeserializeSymmetricCipherToMessage: no key type\n";
    return false;
  }
  cipher_name_ = new string(message.key_type().c_str());
  num_key_bits_ = message.key_bit_size();
  if (!message.has_value()) {
    LOG(ERROR) << "DeserializeSymmetricCipherToMessage: no key\n";
    return false;
  }
  key_ = new byte[Aes::BLOCKBYTESIZE];
  if (Base64ToByteLeftToRight((char*)message.value().c_str(),
                              Aes::BLOCKBYTESIZE, key_) < 0) {
    LOG(ERROR)
        << "DeserializeSymmetricCipherToMessage: can't base64 encode key\n";
    return false;
  }
  return true;
}

void SymmetricCipher::PrintSymmetricKey() {
  if (cipher_name_ == nullptr) {
    printf("no cipher name\n");
    return;
  } else {
    printf("cipher name: %s\n", cipher_name_->c_str());
  }
  if (direction_ == ENCRYPT) {
    printf("encrypt\n");
  } else if (direction_ == DECRYPT) {
    printf("decrypt\n");
  } else if (direction_ == BOTH) {
    printf("encrypt and decrypt\n");
  } else {
    printf("no key direction\n");
  }
  if (initialized_) {
    printf("symmetric key initialized\n");
  } else {
    printf("symmetric key uninitialized\n");
  }
  if (key_ == nullptr) {
    printf("No key\n");
  } else {
    printf("%d key bits: ", num_key_bits_);
    PrintBytes(num_key_bits_ / NBITSINBYTE, key_);
    printf("\n");
  }
}
