// Copyright 2020 John Manferdelli, All Rights Reserved.
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
// File: entropy_accumulate.h

#ifndef _CRYPTO_ENTROPY_ACCUMULATE_H__
#define _CRYPTO_ENTROPY_ACCUMULATE_H__
#include "crypto_support.h"
#include "sha256.h"


// Hash mixer
class entropy_accumulate {
  enum {MAXPOOL_SIZE = 64};   // size in bytes
public:
  double current_entropy_in_pool_;
  int current_size_pool_;     // bytes in pool buffer
  int pool_size_;             // total pool size
  byte pool_[MAXPOOL_SIZE];

  entropy_accumulate();
  ~entropy_accumulate();

  int current_pool_size() {return current_size_pool_;};
  int max_pool_size() {return pool_size_;};
  double entropy_estimate();
  bool add_samples(int num_samples, byte* samples, double est_ent_per_byte);
  bool empty_pool(int* size_of_pool, byte* pool, double* ent);
};
#endif


