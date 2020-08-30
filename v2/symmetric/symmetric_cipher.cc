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
// File: symmetric_cipher.cc

#include "crypto_support.h"
#include "aes.h"
#include "symmetric_cipher.h"

symmetric_cipher::symmetric_cipher() {
  direction_ = NONE;
  cipher_name_ = nullptr;
  initialized_ = false;
  num_key_bits_ = 0;
  key_ = nullptr;
}

symmetric_cipher::~symmetric_cipher() {
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
