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
// File: test_rng.cc

#include <gflags/gflags.h>

#include <stdio.h>
#include "crypto_support.h"
#include "probability_support.h"
#include "entropy_collection.h"
#include "hash_drng.h"
#include "nist_hash_rng.h"

DEFINE_bool(print_all, false, "Print intermediate test computations");
DEFINE_int32(pool_size, 4096, "pool size");
DEFINE_int32(entropy_per_sample, 2, "entropy per sample");
DEFINE_double(entropy_required, 256, "entropy required");

nist_hash_rng the_rng;

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  init_crypto();

  if (!the_rng.initialize(FLAGS_entropy_per_sample, FLAGS_entropy_required)) {
    printf("RNG init failed\n");
    return 1;
  }
  the_rng.raw_entropy_.set_policy(FLAGS_entropy_per_sample);

  // append some samples
  int num_samples = 300;
  byte samples[num_samples];
  if (crypto_get_random_bytes(num_samples, samples) < 0) {
    printf("Can't get crypto bytes\n");
    return 1;
  }
  if (!the_rng.raw_entropy_.append_samples(num_samples, samples)) {
    printf("append samples failed\n");
    return 1;
  }

  // check entropy of pool

  // test health
  // bool health_check();

  // empty pool and init DBRNG
  int size_init_pool = num_samples;
  byte init_pool[num_samples];
  double ent_in_pool= 0.0;
  if (!the_rng.raw_entropy_.empty_pool(&size_init_pool, init_pool, &ent_in_pool)) {
    printf("Can't empty pool\n");
    return 1;
  }
  int size_nonce = 0;
  int size_personalization = 0;
  if (!the_rng.drng_.init(size_nonce, nullptr, size_personalization,
            nullptr, size_init_pool, init_pool, ent_in_pool)) {
    printf("Can't init drng\n");
    return 1;
  }

  // mix in some more entropy
  // the_rng.drng_.mix_new_entropy(int entropy_width, byte* entropy, double ent);

  // generate some numbers
  int num_bits_needed = 256;
  byte out[32];
  if (the_rng.reseed_ctr() >= the_rng.reseed_interval()) {
    // shouldn't happen
    printf("Reseed so fast?\n");
    return 1;
  }
  if (!the_rng.drng_.generate_random_bits(num_bits_needed, out, 0, nullptr)) {
    printf("Can't get bits\n");
    return 1;
  }

  if (FLAGS_print_all) {
    printf("\nBits from drng:\n");
    print_bytes(num_bits_needed / NBITSINBYTE, out);
  }

  close_crypto();
  printf("\n");

  return 0;
}
