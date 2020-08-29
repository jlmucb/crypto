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
// File: hash.cc

#include "crypto_support.h"
#include "hash.h"

crypto_hash::crypto_hash() {
  hash_name_ = nullptr;
  finalized_ = false;
}

crypto_hash::~crypto_hash() {
  if (hash_name_ != nullptr) {
    delete hash_name_;
    hash_name_ = nullptr;
  }
  finalized_ = false;
}
