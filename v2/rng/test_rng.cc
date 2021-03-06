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
DEFINE_int(pool_size, 4096, "pool size");
DEFINE_int(entropy_per_sample, 2, "entropy per sample");
DEFINE_double(entropy_required, 256, "entropy required");

nist_hash_rng the_rng;

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  init_crypto();

  if (!the_rng.initialize(FLAGS_entropy_per_sample, FLAGS_entropy_required)) {
    printf("RNG init failed\n");
    return 1;
  }
  the_rng.set_policy(FLAGS_pool_size, FLAGS_entropy_per_sample);

  // append some samples
  // bool append_samples(int num_samples, byte* samples);
  // check entropy of pool
  // test health
  // bool health_check();

  // empty pool and init DBRNG
  // bool empty_pool(int* size_of_pool, byte* pool, double* ent);

  // mix in some more entropy

  // generate some numbers

  close_crypto();
  printf("\n");

  return 0;
}
