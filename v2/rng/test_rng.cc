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
DEFINE_double(entropy_required, 128, "entropy required");

DEFINE_int32(n_sample, 8, "sample size");               // sample size in bits (<=8)
DEFINE_double(h_submitter, 4.0, "submitter entropy");   // per sample
DEFINE_double(h_original, 4.0, "measured entropy");     // per sample
DEFINE_double(h_bitstring, 0.5, "bitstring entropy");  // per bit

nist_hash_rng the_rng;

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  init_crypto();

  double h_estimate= ((double)(FLAGS_n_sample)) * FLAGS_h_bitstring;
  if (FLAGS_h_original < h_estimate)
    h_estimate= FLAGS_h_original;
  if (FLAGS_h_submitter < h_estimate)
    h_estimate= FLAGS_h_submitter;

  if (!the_rng.initialize(FLAGS_n_sample, h_estimate, FLAGS_entropy_required, 1024)) {
    printf("RNG init failed\n");
    return 1;
  }
  the_rng.raw_entropy_.set_policy(the_rng.h_estimate_);

  // append some samples
  int num_samples = 100;
  byte samples[num_samples];
  if (crypto_get_random_bytes(num_samples, samples) < 0) {
    printf("Can't get crypto bytes\n");
    return 1;
  }

  if (!the_rng.collect_samples(num_samples, samples)) {
    printf("collect_samples failed\n");
    return 1;
  }

  // do restart tests someday
  if (!the_rng.restart_test(num_samples, samples)) {
    printf("restart tests failed\n");
    return 1;
  }

  // bool health_check();
  if (!the_rng.health_test(num_samples, samples)) {
    printf("restart test failed\n");
  }

  // empty pool and init drng
  int size_init_pool = num_samples;
  byte init_pool[num_samples];
  double ent_in_pool= 0.0;
  if (!the_rng.raw_entropy_.empty_pool(&size_init_pool, init_pool, &ent_in_pool)) {
    printf("Can't empty pool\n");
    return 1;
  }
  printf("Entropy in pool : %7.3lf bits\n", ent_in_pool);

  int size_nonce = 0;
  int size_personalization = 0;
  if (!the_rng.drng_.init(size_nonce, nullptr, size_personalization,
            nullptr, size_init_pool, init_pool, ent_in_pool)) {
    printf("Can't init drng\n");
    return 1;
  }
  printf("Entropy in drng : %7.3lf bits\n", the_rng.drng_.current_entropy());

  // generate some numbers
  int num_bits_needed = 256;
  byte out[32];
  if (the_rng.reseed_ctr() >= the_rng.reseed_interval()) {
    // shouldn't happen
    printf("Reseed so fast?\n");
    return 1;
  }

  printf("Required entropy: %d bits\n", the_rng.required_entropy_to_extract());
  if (the_rng.required_entropy_to_extract() > the_rng.drng_.current_entropy()) {
    printf("Not enough entropy\n");
    return 1;
  }

  printf("\n");
  for (int j = 0; j < 10; j++) {
    if (!the_rng.extract_random_number(num_bits_needed, out)) {
      printf("Can't get bits\n");
      return 1;
    }

    if (FLAGS_print_all) {
      printf("Bits from drng: ");
      print_bytes(num_bits_needed / NBITSINBYTE, out);
    }
  }

  close_crypto();
  printf("\n");

  return 0;
}
