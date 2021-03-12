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
// File: test_jitter_collection.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "crypto_names.h"
#include "entropy_collection.h"
#include "probability_support.h"
#include "aes.h"


DEFINE_bool(print_all, false, "Print intermediate test computations");
DEFINE_string(graph_file_name, "jitter.bin", "jitter file");

volatile void inline test_code(int k) {
  volatile int  t = 0;

  for (int i = 0; i < k; i++) {
    t += i;
  }
  t /= 2;
}

bool test_jitter1(int n) {
  uint64_t cpc = calibrate_rdtsc();
  printf ("%lld cpc\n", cpc);

  uint64_t t1, t2;
  uint32_t delta;

  int num_samples = n;
  uint32_t delta_array[num_samples];
  
  for (int i = 0; i < num_samples; i++) {
    t1 = read_rdtsc();
    test_code(5);
    t2 = read_rdtsc();
    delta = t2 - t1;
    delta_array[i] = delta / 2;
    // printf ("t1: %lld, t2: %lld, delta: %lld\n", t1, t2, delta);
  }

  int nbins = 120;
  uint32_t bins[nbins];
  if (!bin_raw_data(num_samples, delta_array, nbins, bins)) {
    printf("Can't bin data\n");
    return false;
  }

  double x[nbins];
  double y[nbins];
  for (int i = 0; i < nbins; i++) {
    x[i] = (double) i;
    y[i] = (double) bins[i];
  }

  if (!write_general_graph_data(FLAGS_graph_file_name, nbins, x, y)) {
    printf("Can't write graph data\n");
    return false;
  }
  return true;
}


TEST (jitter, test_jitter) {
  EXPECT_TRUE(test_jitter1(100));
}

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  init_crypto();

  int result = RUN_ALL_TESTS();

  close_crypto();
  printf("\n");
  return result;
}
