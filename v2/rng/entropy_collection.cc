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
  pool_size_ = MAXPOOL_SIZE;
  memset(pool_, 0, MAXPOOL_SIZE);
  memset(compressed_entropy_, 0, sha256::DIGESTBYTESIZE);
  compressed_entropy_flag_ = false;
  compressed_entropy_ent_ = 0;
}

entropy_collection::~entropy_collection() {
  current_entropy_in_pool_= 0;
  current_size_pool_ = 0;
  pool_size_ = MAXPOOL_SIZE;
  memset(pool_, 0, MAXPOOL_SIZE);
  memset(compressed_entropy_, 0, sha256::DIGESTBYTESIZE);
  compressed_entropy_flag_ = false;
  compressed_entropy_ent_ = 0;
}

void entropy_collection::set_policy(double entropy_per_sample) {
  entropy_per_sample_ = entropy_per_sample;
  initialized_ = true;
}

// samples are always 8 bits
bool entropy_collection::append_samples(int num_samples, byte_t* samples) {
  if (!initialized_)
    return false;

  if ((num_samples + current_size_pool_) > pool_size_)
    return false;
  memcpy(&pool_[current_size_pool_], samples, num_samples);
  current_size_pool_ += num_samples;
  current_entropy_in_pool_ += ((double)num_samples) * entropy_per_sample_;
  return true;
}

bool entropy_collection::add_samples(int num_samples, byte_t* samples) {
  int total = num_samples + current_size_pool_;
  int fits = 0;
  int left_over = 0;

  if (total < pool_size_) {
    fits = num_samples;
  } else {
    fits = total - pool_size_;
    left_over = num_samples - fits;
  }

  if (!append_samples(fits, samples)) {
    return false;
  }

  if (current_size_pool_ >= pool_size_) {
    sha256 obj;

    obj.init();
    if (compressed_entropy_flag_) {
      obj.add_to_hash(sha256::DIGESTBYTESIZE, compressed_entropy_);
    }
    obj.add_to_hash(current_size_pool_, pool_);
    obj.get_digest(sha256::DIGESTBYTESIZE, compressed_entropy_);
    compressed_entropy_flag_ = true;
    compressed_entropy_ent_ = conditioned_entropy_estimate(compressed_entropy_ent_ +
        current_entropy_in_pool_ + ((double)fits) * entropy_per_sample_,
        NBITSINBYTE * sha256::DIGESTBYTESIZE,
        NBITSINBYTE * (current_entropy_in_pool_ + sha256::DIGESTBYTESIZE),
        NBITSINBYTE * sha256::DIGESTBYTESIZE);
    current_size_pool_ = 0;
    current_entropy_in_pool_ = 0;
    append_samples(left_over, &samples[fits]);
  }
  return true;
}

double entropy_collection::entropy_estimate() {
  return current_entropy_in_pool_ + compressed_entropy_ent_;
}

bool entropy_collection::empty_pool(int* size_of_output, byte_t* data, double* ent) {
  if (*size_of_output < current_size_pool_) {
    printf("output too small, size of data:  %d, size of pool: %d\n", *size_of_output, current_size_pool_);
    return false;
  }
  memcpy(data, pool_, current_size_pool_);

  if (compressed_entropy_flag_) {
    if ((*size_of_output - current_size_pool_) < sha256::DIGESTBYTESIZE)
      return false;
    memcpy(&data[current_size_pool_], compressed_entropy_, sha256::DIGESTBYTESIZE);
    *size_of_output = current_size_pool_ + sha256::DIGESTBYTESIZE;
  } else {
    *size_of_output = current_size_pool_;
  }
  
  *ent = conditioned_entropy_estimate(compressed_entropy_ent_ + current_entropy_in_pool_,
        NBITSINBYTE * sha256::DIGESTBYTESIZE,
        NBITSINBYTE * (sha256::DIGESTBYTESIZE + current_entropy_in_pool_),
        NBITSINBYTE * (*size_of_output));
  current_entropy_in_pool_= 0;
  current_size_pool_ = 0;
  compressed_entropy_ent_ = 0;
  memset(pool_, 0, MAXPOOL_SIZE);
  memset(compressed_entropy_, 0, sha256::DIGESTBYTESIZE);
  compressed_entropy_flag_ = false;
  return true;
}
