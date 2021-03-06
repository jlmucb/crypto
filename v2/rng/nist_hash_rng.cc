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
      double required_entropy_to_extract) {
  required_entropy_to_extract_= required_entropy_to_extract;
  return true;
}

bool nist_hash_rng::collect_samples(int num_samples, byte* samples) {
  return true;
}

bool nist_hash_rng::initialize_collector() {
  return true;
}

bool nist_hash_rng::initialize_drng() {
  return true;
}

bool nist_hash_rng::mix_new_samples(int num_samples, byte* samples) {
  return true;
}

int nist_hash_rng::extract_random_number(int num_bits, byte* rn) {
  return 0;
}

bool nist_hash_rng::reseed() {
  return true;
}
