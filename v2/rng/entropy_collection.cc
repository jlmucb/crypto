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
// File: entropy_collection.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "crypto_names.h"
#include "probability_support.h"
#include "hash_df.h"
#include "entropy_collection.h"


entropy_collection::entropy_collection() {
  current_entropy_in_pool_= 0;
  current_size_pool_ = 0;
  memset(pool_, 0, MAXPOOL_SIZE);
}

entropy_collection::~entropy_collection() {
  current_entropy_in_pool_= 0;
  current_size_pool_ = 0;
  pool_size_ = MAXPOOL_SIZE;
  memset(pool_, 0, MAXPOOL_SIZE);
}

void entropy_collection::set_policy(double entropy_per_sample) {
  entropy_per_sample_ = entropy_per_sample;
  initialized_ = true;
}

// samples are always 8 bits
bool entropy_collection::append_samples(int num_samples, byte* samples) {
  if (!initialized_)
    return false;

  if ((num_samples + current_size_pool_) > pool_size_)
    return false;
  memcpy(&pool_[current_size_pool_], samples, num_samples);
  current_size_pool_ += num_samples;
  current_entropy_in_pool_ += ((double)num_samples) * entropy_per_sample_;
  return true;
}

double entropy_collection::entropy_estimate() {
  return current_entropy_in_pool_;
}

bool entropy_collection::health_check() {
  return true;
}

bool entropy_collection::empty_pool(int* size_of_pool, byte* data, double* ent) {
  if (*size_of_pool < current_size_pool_)
    return false;
  memcpy(data, pool_, current_size_pool_);
  *size_of_pool = current_size_pool_;
  *ent = current_entropy_in_pool_;
  
  current_entropy_in_pool_= 0;
  current_size_pool_ = 0;
  memset(pool_, 0, MAXPOOL_SIZE);
}