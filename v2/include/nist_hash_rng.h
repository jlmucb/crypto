// Copyright 2020 John Manferdelli, All Rights Reserved.
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
// File: nist_hash_rng.h

#ifndef _CRYPTO_NIST_HASH_RNG_H__
#define _CRYPTO_NIST_HASH_RNG_H__
#include "crypto_support.h"
#include "sha256.h"
#include "hash_drng.h"

class nist_hash_rng {
public:
  entropy_collection raw_entropy_;
  hash_drng drng_;
  int reseed_interval_;
  int reseed_ctr_;
  int required_entropy_to_extract_;

  nist_hash_rng();
  ~nist_hash_rng();

  int reseed_interval() {return reseed_interval_;}
  int reseed_ctr() {return reseed_ctr_;}
  int required_entropy_to_extract() {return required_entropy_to_extract_;}

  bool initialize(int entropy_per_sample, double required_entropy_to_extract);
  bool collect_samples(int num_samples, byte* samples);

  bool initialize_drng();
  bool mix_new_samples(int num_samples, byte* samples);
  int extract_random_number(int num_bits, byte* rn);

  bool reseed();
  bool restart_test(int num_samples, byte* samples);
};
#endif


