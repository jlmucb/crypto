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
// File: nist_hash_rng.cc

#include <stdio.h>
#include "crypto_support.h"
#include "probability_support.h"
#include "entropy_collection.h"
#include "hash_drng.h"
#include "nist_hash_rng.h"


nist_hash_rng::nist_hash_rng() {
}

nist_hash_rng::~nist_hash_rng() {
}

bool nist_hash_rng::initialize(int entropy_per_sample,
      double required_entropy_to_extract, int reseed_interval) {
  required_entropy_to_extract_= required_entropy_to_extract;
  reseed_interval_ = reseed_interval;
  return true;
}

bool nist_hash_rng::collect_samples(int num_samples, byte* samples) {
  return raw_entropy_.add_samples(num_samples, samples);
}

bool nist_hash_rng::initialize_drng() {
  int size_init_data = raw_entropy_.pool_size_ + sha256::DIGESTBYTESIZE;
  byte data[size_init_data];
  double pool_entropy = 0;

  memset(data, 0, size_init_data);
  if (!raw_entropy_.empty_pool(&size_init_data, data, &pool_entropy)) {
    printf("Can't empty entropy pool\n");
    return false;
  }
  return drng_.init(0, nullptr, 0, nullptr, size_init_data, data,
            pool_entropy);
  return true;
}

int nist_hash_rng::extract_random_number(int num_bits, byte* rn) {
  return drng_.generate_random_bits(num_bits, rn, 0, nullptr);
}

bool nist_hash_rng::reseed() {
  return true;
}

bool nist_hash_rng::restart_test(int num_samples, byte* samples) {
  return true;
}

