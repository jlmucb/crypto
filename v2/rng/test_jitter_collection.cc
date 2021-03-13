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
DEFINE_int32(num_samples, 100, "number of samples");
DEFINE_int32(num_loops, 5, "number of loops in test_code");

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wunknown-pragmas"

#pragma GCC push_options
#pragma GCC optimize ("O0")
volatile void inline test_code(int k) {
  volatile int  t = 0;

  for (int i = 0; i < k; i++) {
    t += i;
  }
  t /= 2;
}
#pragma GCC pop_options

bool test_jitter1(int num_samples, int num_loops) {
  uint64_t cpc = calibrate_rdtsc();

  if (FLAGS_print_all) {
    printf ("%lld cpc\n\n", cpc);
  }

  uint64_t t1, t2;
  uint32_t delta;

  uint32_t delta_array[num_samples];
  
  for (int i = 0; i < num_samples; i++) {
    t1 = read_rdtsc();
    test_code(num_loops);
    t2 = read_rdtsc();
    delta = t2 - t1;
    delta_array[i] = delta / 2;
    // printf ("t1: %lld, t2: %lld, delta: %lld\n", t1, t2, delta);
  }

  if (FLAGS_print_all) {
    printf("delta_array:\n");
    print_uint32_array(num_samples, delta_array);
    printf("\n");
  }

  int nbins = 120;
  uint32_t bins[nbins];
  if (!bin_raw_data(num_samples, delta_array, nbins, bins)) {
    printf("Can't bin data\n");
    return false;
  }


  int upper_bin;
  int lower_bin;;
  for (upper_bin = (nbins - 1); upper_bin > 20; upper_bin--) {
    if (bins[upper_bin] != 0)
      break;
  }
  for (lower_bin = 0; lower_bin < upper_bin; lower_bin++) {
    if (bins[lower_bin] != 0)
      break;
  }
  lower_bin -= 5;
  upper_bin += 5;

  if (FLAGS_print_all) {
    printf("bins form %d to %d:\n", lower_bin, upper_bin);
    print_uint32_array(upper_bin - lower_bin, &bins[lower_bin]);
    printf("\n");
  }

  double p[nbins];
  double expected = 0.0;
  for (int i = 0; i < nbins; i++) {
    p[i] = ((double)bins[i]) / ((double) num_samples);
    expected += p[i] * ((double) i);
  }

  if (FLAGS_print_all) {
    int k = 0;
    printf("probabilities:\n");
    for (int i = lower_bin;  i < upper_bin; i++) {
      if (p[i] <= 0.0)
        continue;
      printf("%03d, %4.3lf;  ", i, p[i]);
      if (((k++)%8) == 7)
        printf("\n");
    }
    printf("\n\n");
  }

  double sh_ent = shannon_entropy(nbins, p);
  double ren_ent = renyi_entropy(nbins, p);
  double min_ent = min_entropy(nbins, p);
  printf("Samples: %d, num_loops: %d, Expected bin: %5.3lf\n", num_samples, num_loops, expected);
  printf("   Shannon entropy: %6.4lf, renyi entropy: %6.4lf, min_entropy: %6.4lf\n",
          sh_ent, ren_ent, min_ent);
  printf("   Shannon entropy/sample: %6.4lf, renyi entropy/sample: %6.4lf, min_entropy/sample: %6.4lf\n",
          sh_ent / ((double)num_samples), ren_ent / ((double)num_samples), min_ent / ((double)num_samples));

  double x[nbins];
  double y[nbins];
  for (int i = 0; i < nbins; i++) {
    x[i] = (double) i;
    y[i] = (double) bins[i];
  }

  if (!write_general_graph_data(FLAGS_graph_file_name, upper_bin - lower_bin,
                                &x[lower_bin], &y[lower_bin])) {
    printf("Can't write graph data\n");
    return false;
  }
  return true;
}


TEST (jitter, test_jitter) {
  EXPECT_TRUE(test_jitter1(FLAGS_num_samples, FLAGS_num_loops));
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
